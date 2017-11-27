import re
from collections import defaultdict, namedtuple
from collections.abc import Iterable
from functools import lru_cache

from sanic.exceptions import NotFound, InvalidUsage
from sanic.views import CompositionView

Route = namedtuple(
    'Route',
    ['handler', 'methods', 'pattern', 'parameters', 'name', 'uri'])
Parameter = namedtuple('Parameter', ['name', 'cast'])

REGEX_TYPES = {
    'string': (str, r'[^/]+'),
    'int': (int, r'\d+'),
    'number': (float, r'[0-9\\.]+'),
    'alpha': (str, r'[A-Za-z]+'),
    'path': (str, r'[^/].*?'),
}

ROUTER_CACHE_SIZE = 1024


def url_hash(url):
    return url.count('/')


class RouteExists(Exception):
    pass


class RouteDoesNotExist(Exception):
    pass


class Router:
    """Router supports basic routing with parameters and method checks

    Usage:

    .. code-block:: python

        @sanic.route('/my/url/<my_param>', methods=['GET', 'POST', ...])
        def my_route(request, my_param):
            do stuff...

    or

    .. code-block:: python

        @sanic.route('/my/url/<my_param:my_type>', methods['GET', 'POST', ...])
        def my_route_with_type(request, my_param: my_type):
            do stuff...

    Parameters will be passed as keyword arguments to the request handling
    function. Provided parameters can also have a type by appending :type to
    the <parameter>. Given parameter must be able to be type-casted to this.
    If no type is provided, a string is expected.  A regular expression can
    also be passed in as the type. The argument given to the function will
    always be a string, independent of the type.
    """
    routes_static = None
    routes_dynamic = None
    routes_always_check = None
    parameter_pattern = re.compile(r'<(.+?)>')

    def __init__(self):
        self.routes_all = {}
        self.routes_names = {}
        self.routes_static_files = {}
        self.routes_static = {}
        self.routes_dynamic = defaultdict(list)
        self.routes_always_check = []
        self.hosts = set()

    @classmethod
    def parse_parameter_string(cls, parameter_string):
        """Parse a parameter string into its constituent name, type, and
        pattern

        For example::

            parse_parameter_string('<param_one:[A-z]>')` ->
                ('param_one', str, '[A-z]')

        :param parameter_string: String to parse
        :return: tuple containing
            (parameter_name, parameter_type, parameter_pattern)
        """
        # We could receive NAME or NAME:PATTERN
        name = parameter_string
        pattern = 'string'
        if ':' in parameter_string:
            name, pattern = parameter_string.split(':', 1)
            if not name:
                raise ValueError(
                    "Invalid parameter syntax: {}".format(parameter_string)
                )

        default = (str, pattern)
        # Pull from pre-configured types
        _type, pattern = REGEX_TYPES.get(pattern, default)

        return name, _type, pattern

    def add(self, uri, methods, handler, host=None, strict_slashes=False,
            version=None, name=None):
        """Add a handler to the route list

        :param uri: path to match
        :param methods: sequence of accepted method names. If none are
            provided, any method is allowed
        :param handler: request handler function.
            When executed, it should provide a response object.
        :param strict_slashes: strict to trailing slash
        :param version: current version of the route or blueprint. See
            docs for further details.
        :return: Nothing
        """
        if version is not None:
            version = re.escape(str(version).strip('/').lstrip('v'))
            uri = "/".join(["/v{}".format(version), uri.lstrip('/')])
        # add regular version
        self._add(uri, methods, handler, host, name)

        if strict_slashes:
            return

        # Add versions with and without trailing /
        slashed_methods = self.routes_all.get(uri + '/', frozenset({}))
        if isinstance(methods, Iterable):
            _slash_is_missing = all(method in slashed_methods for
                                    method in methods)
        else:
            _slash_is_missing = methods in slashed_methods

        slash_is_missing = (
            not uri[-1] == '/' and not _slash_is_missing
        )
        without_slash_is_missing = (
            uri[-1] == '/' and not
            self.routes_all.get(uri[:-1], False) and not
            uri == '/'
        )
        # add version with trailing slash
        if slash_is_missing:
            self._add(uri + '/', methods, handler, host, name)
        # add version without trailing slash
        elif without_slash_is_missing:
            self._add(uri[:-1], methods, handler, host, name)

    def _add(self, uri, methods, handler, host=None, name=None):
        """Add a handler to the route list

        :param uri: path to match
        :param methods: sequence of accepted method names. If none are
            provided, any method is allowed
        :param handler: request handler function.
            When executed, it should provide a response object.
        :param name: user defined route name for url_for
        :return: Nothing
        """
        if host is not None:
            if isinstance(host, str):
                uri = host + uri
                self.hosts.add(host)

            else:
                if not isinstance(host, Iterable):
                    raise ValueError("Expected either string or Iterable of "
                                     "host strings, not {!r}".format(host))

                for host_ in host:
                    self.add(uri, methods, handler, host_, name)
                return

        # Dict for faster lookups of if method allowed
        if methods:
            methods = frozenset(methods)

        parameters = []
        properties = {"unhashable": None}

        def add_parameter(match):
            name = match.group(1)
            name, _type, pattern = self.parse_parameter_string(name)

            parameter = Parameter(
                name=name, cast=_type)
            parameters.append(parameter)

            # Mark the whole route as unhashable if it has the hash key in it
            if re.search(r'(^|[^^]){1}/', pattern):
                properties['unhashable'] = True
            # Mark the route as unhashable if it matches the hash key
            elif re.search(r'/', pattern):
                properties['unhashable'] = True

            return '({})'.format(pattern)

        pattern_string = re.sub(self.parameter_pattern, add_parameter, uri)
        pattern = re.compile(r'^{}$'.format(pattern_string))

        def merge_route(route, methods, handler):
            # merge to the existing route when possible.
            if not route.methods or not methods:
                # method-unspecified routes are not mergeable.
                raise RouteExists(
                    "Route already registered: {}".format(uri))
            elif route.methods.intersection(methods):
                # already existing method is not overloadable.
                duplicated = methods.intersection(route.methods)
                raise RouteExists(
                    "Route already registered: {} [{}]".format(
                        uri, ','.join(list(duplicated))))
            if isinstance(route.handler, CompositionView):
                view = route.handler
            else:
                view = CompositionView()
                view.add(route.methods, route.handler)
            view.add(methods, handler)
            route = route._replace(
                handler=view, methods=methods.union(route.methods))
            return route

        if parameters:
            # TODO: This is too complex, we need to reduce the complexity
            if properties['unhashable']:
                routes_to_check = self.routes_always_check
                ndx, route = self.check_dynamic_route_exists(
                    pattern, routes_to_check)
            else:
                routes_to_check = self.routes_dynamic[url_hash(uri)]
                ndx, route = self.check_dynamic_route_exists(
                    pattern, routes_to_check)
            if ndx != -1:
                # Pop the ndx of the route, no dups of the same route
                routes_to_check.pop(ndx)
        else:
            route = self.routes_all.get(uri)

        # prefix the handler name with the blueprint name
        # if available
        # special prefix for static files
        is_static = False
        if name and name.startswith('_static_'):
            is_static = True
            name = name.split('_static_', 1)[-1]

        if hasattr(handler, '__blueprintname__'):
            handler_name = '{}.{}'.format(
                handler.__blueprintname__, name or handler.__name__)
        else:
            handler_name = name or getattr(handler, '__name__', None)

        if route:
            route = merge_route(route, methods, handler)
        else:
            route = Route(
                handler=handler, methods=methods, pattern=pattern,
                parameters=parameters, name=handler_name, uri=uri)

        self.routes_all[uri] = route
        if is_static:
            pair = self.routes_static_files.get(handler_name)
            if not (pair and (pair[0] + '/' == uri or uri + '/' == pair[0])):
                self.routes_static_files[handler_name] = (uri, route)

        else:
            pair = self.routes_names.get(handler_name)
            if not (pair and (pair[0] + '/' == uri or uri + '/' == pair[0])):
                self.routes_names[handler_name] = (uri, route)

        if properties['unhashable']:
            self.routes_always_check.append(route)
        elif parameters:
            self.routes_dynamic[url_hash(uri)].append(route)
        else:
            self.routes_static[uri] = route

    @staticmethod
    def check_dynamic_route_exists(pattern, routes_to_check):
        for ndx, route in enumerate(routes_to_check):
            if route.pattern == pattern:
                return ndx, route
        else:
            return -1, None

    def remove(self, uri, clean_cache=True, host=None):
        if host is not None:
            uri = host + uri
        try:
            route = self.routes_all.pop(uri)
            for handler_name, pairs in self.routes_names.items():
                if pairs[0] == uri:
                    self.routes_names.pop(handler_name)
                    break

            for handler_name, pairs in self.routes_static_files.items():
                if pairs[0] == uri:
                    self.routes_static_files.pop(handler_name)
                    break

        except KeyError:
            raise RouteDoesNotExist("Route was not registered: {}".format(uri))

        if route in self.routes_always_check:
            self.routes_always_check.remove(route)
        elif url_hash(uri) in self.routes_dynamic \
                and route in self.routes_dynamic[url_hash(uri)]:
            self.routes_dynamic[url_hash(uri)].remove(route)
        else:
            self.routes_static.pop(uri)

        if clean_cache:
            self._get.cache_clear()

    @lru_cache(maxsize=ROUTER_CACHE_SIZE)
    def find_route_by_view_name(self, view_name, name=None):
        """Find a route in the router based on the specified view name.

        :param view_name: string of view name to search by
        :param kwargs: additional params, usually for static files
        :return: tuple containing (uri, Route)
        """
        if not view_name:
            return (None, None)

        if view_name == 'static' or view_name.endswith('.static'):
            return self.routes_static_files.get(name, (None, None))

        return self.routes_names.get(view_name, (None, None))

    def get(self, request):
        """Get a request handler based on the URL of the request, or raises an
        error

        :param request: Request object
        :return: handler, arguments, keyword arguments
        """
        # No virtual hosts specified; default behavior
        if not self.hosts:
            return self._get(request.path, request.method, '')
        # virtual hosts specified; try to match route to the host header
        try:
            return self._get(request.path, request.method,
                             request.headers.get("Host", ''))
        # try default hosts
        except NotFound:
            return self._get(request.path, request.method, '')

    @lru_cache(maxsize=ROUTER_CACHE_SIZE)
    def _get(self, url, method, host):
        """Get a request handler based on the URL of the request, or raises an
        error.  Internal method for caching.

        :param url: request URL
        :param method: request method
        :return: handler, arguments, keyword arguments
        """
        url = host + url
        # Check against known static routes
        route = self.routes_static.get(url)
        method_not_supported = InvalidUsage(
            'Method {} not allowed for URL {}'.format(
                method, url), status_code=405)
        if route:
            if route.methods and method not in route.methods:
                raise method_not_supported
            match = route.pattern.match(url)
        else:
            route_found = False
            # Move on to testing all regex routes
            for route in self.routes_dynamic[url_hash(url)]:
                match = route.pattern.match(url)
                route_found |= match is not None
                # Do early method checking
                if match and method in route.methods:
                    break
            else:
                # Lastly, check against all regex routes that cannot be hashed
                for route in self.routes_always_check:
                    match = route.pattern.match(url)
                    route_found |= match is not None
                    # Do early method checking
                    if match and method in route.methods:
                        break
                else:
                    # Route was found but the methods didn't match
                    if route_found:
                        raise method_not_supported
                    raise NotFound('Requested URL {} not found'.format(url))

        kwargs = {p.name: p.cast(value)
                  for value, p
                  in zip(match.groups(1), route.parameters)}
        route_handler = route.handler
        if hasattr(route_handler, 'handlers'):
            route_handler = route_handler.handlers[method]
        return route_handler, [], kwargs, route.uri

    def is_stream_handler(self, request):
        """ Handler for request is stream or not.
        :param request: Request object
        :return: bool
        """
        try:
            handler = self.get(request)[0]
        except (NotFound, InvalidUsage):
            return False
        if (hasattr(handler, 'view_class') and
                hasattr(handler.view_class, request.method.lower())):
            handler = getattr(handler.view_class, request.method.lower())
        return hasattr(handler, 'is_stream')



from werkzeug.routing import Map, Rule


def _endpoint_from_view_func(view_func):
    return view_func.__name__


class WerkzeugRouter:

    url_rule_class = Rule

    def __init__(self):
        self.url_map = Map()
        self.view_functions = {}

    def add(self, uri, methods, handler, host=None):
        options = {}
        if host:
            options['host'] = host
        self.add_url_rule(uri, view_func=handler, methods=methods, **options)

    def add_url_rule(self, rule, endpoint=None, view_func=None, **options):
        """Connects a URL rule.  Works exactly like the :meth:`route`
        decorator.  If a view_func is provided it will be registered with the
        endpoint.

        Basically this example::

            @app.route('/')
            def index():
                pass

        Is equivalent to the following::

            def index():
                pass
            app.add_url_rule('/', 'index', index)

        If the view_func is not provided you will need to connect the endpoint
        to a view function like so::

            app.view_functions['index'] = index

        Internally :meth:`route` invokes :meth:`add_url_rule` so if you want
        to customize the behavior via subclassing you only need to change
        this method.

        :param rule: the URL rule as string
        :param endpoint: the endpoint for the registered URL rule.  Flask
                         itself assumes the name of the view function as
                         endpoint
        :param view_func: the function to call when serving a request to the
                          provided endpoint
        :param options: the options to be forwarded to the underlying
                        :class:`~werkzeug.routing.Rule` object.  A change
                        to Werkzeug is handling of method options.  methods
                        is a list of methods this rule should be limited
                        to (``GET``, ``POST`` etc.).  By default a rule
                        just listens for ``GET`` (and implicitly ``HEAD``).
                        Starting with Flask 0.6, ``OPTIONS`` is implicitly
                        added and handled by the standard request handling.
        """
        if endpoint is None:
            endpoint = _endpoint_from_view_func(view_func)
        options['endpoint'] = endpoint
        methods = options.pop('methods', None)

        # if the methods are not given and the view_func object knows its
        # methods we can use that instead.  If neither exists, we go with
        # a tuple of only ``GET`` as default.
        if methods is None:
            methods = getattr(view_func, 'methods', None) or ('GET',)
        if isinstance(methods, str):
            raise TypeError('Allowed methods have to be iterables of strings, '
                            'for example: @app.route(..., methods=["POST"])')
        methods = set(item.upper() for item in methods)

        # Methods that should always be added
        required_methods = set(getattr(view_func, 'required_methods', ()))

        # starting with Flask 0.8 the view_func object can disable and
        # force-enable the automatic options handling.
        provide_automatic_options = getattr(view_func,
            'provide_automatic_options', None)

        if provide_automatic_options is None:
            if 'OPTIONS' not in methods:
                provide_automatic_options = True
                required_methods.add('OPTIONS')
            else:
                provide_automatic_options = False

        # Add the required methods now.
        methods |= required_methods

        rule = self.url_rule_class(rule, methods=methods, **options)
        rule.provide_automatic_options = provide_automatic_options

        self.url_map.add(rule)
        if view_func is not None:
            old_func = self.view_functions.get(endpoint)
            if old_func is not None and old_func != view_func:
                raise AssertionError('View function mapping is overwriting an '
                                     'existing endpoint function: %s' % endpoint)
            self.view_functions[endpoint] = view_func

    def create_url_adapter(self, request):
        """Creates a URL adapter for the given request.  The URL adapter
        is created at a point where the request context is not yet set up
        so the request is passed explicitly.
        """
        adapter = self.url_map.bind('127.0.0.1')  # fixme
        print(adapter.map)
        return adapter

    def dispatch_request(self, req, rule):
        """Does the request dispatching.  Matches the URL and returns the
        return value of the view or error handler.  This does not have to
        be a response object.

        """
        # if we provide automatic options for this URL and the
        # request came with the OPTIONS method, reply automatically
        if getattr(rule, 'provide_automatic_options', False) \
           and req.method == 'OPTIONS':
            return self.make_default_options_response()
        # otherwise dispatch to the handler for that endpoint
        view_function = self.view_functions[rule.endpoint]
        return view_function

    def get(self, request):
        try:
            url_adapter = self.create_url_adapter(request)
            url_rule, view_args = url_adapter.match(request.url, request.method, return_rule=True)
        except:
            raise
        view_function = self.dispatch_request(request, url_rule)
        return view_function, [], view_args, '/'

    def remove(self, uri, clean_cache, host=None):
        pass
