import re
from collections import defaultdict, namedtuple
from functools import lru_cache
from .config import Config
from .exceptions import NotFound, InvalidUsage

Route = namedtuple('Route', ['handler', 'methods', 'pattern', 'parameters'])
Parameter = namedtuple('Parameter', ['name', 'cast'])

REGEX_TYPES = {
    'string': (str, r'[^/]+'),
    'int': (int, r'\d+'),
    'number': (float, r'[0-9\\.]+'),
    'alpha': (str, r'[A-Za-z]+'),
}

DEFAULT_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']


def url_hash(url):
    return url.count('/')


class RouteExists(Exception):
    pass


class RouteDoesNotExist(Exception):
    pass


class Router:
    """
    Router supports basic routing with parameters and method checks
    Usage:
        @app.route('/my_url/<my_param>', methods=['GET', 'POST', ...])
        def my_route(request, my_param):
            do stuff...
    or
        @app.route('/my_url/<my_param:my_type>', methods=['GET', 'POST', ...])
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

    def __init__(self):
        self.routes_405 = {}
        self.routes_all = {}
        self.routes_static = {}
        self.routes_dynamic = defaultdict(list)
        self.routes_always_check = []
        self.hosts = None

    def add(self, uri, methods, handler, host=None):
        """
        Adds a handler to the route list
        :param uri: Path to match
        :param methods: Array of accepted method names.
        If none are provided, any method is allowed
        :param handler: Request handler function.
        When executed, it should provide a response object.
        :return: Nothing
        """
        if host is not None:
            # we want to track if there are any
            # vhosts on the Router instance so that we can
            # default to the behavior without vhosts
            if self.hosts is None:
                self.hosts = set(host)
            else:
                self.hosts.add(host)
            uri = host + uri

        # Dict for faster lookups of if method allowed
        if methods:
            # Force methods always to be upper
            methods = frozenset([method.upper() for method in methods])
        else:
            methods = DEFAULT_METHODS

        for method in methods:
            if (uri, method) in self.routes_all:
                raise RouteExists(
                    "Route already registered: {} [{}]".format(uri, method))

        parameters = []
        properties = {"unhashable": None}

        def add_parameter(match):
            # We could receive NAME or NAME:PATTERN
            name = match.group(1)
            pattern = 'string'
            if ':' in name:
                name, pattern = name.split(':', 1)

            default = (str, pattern)
            # Pull from pre-configured types
            _type, pattern = REGEX_TYPES.get(pattern, default)
            parameter = Parameter(name=name, cast=_type)
            parameters.append(parameter)

            # Mark the whole route as unhashable if it has the hash key in it
            if re.search('(^|[^^]){1}/', pattern):
                properties['unhashable'] = True
            # Mark the route as unhashable if it matches the hash key
            elif re.search(pattern, '/'):
                properties['unhashable'] = True

            return '({})'.format(pattern)

        pattern_string = re.sub(r'<(.+?)>', add_parameter, uri)
        pattern = re.compile(r'^{}$'.format(pattern_string))

        route = Route(
            handler=handler, methods=methods, pattern=pattern,
            parameters=parameters)

        for method in methods:
            self.routes_all[uri, method] = route

        if properties['unhashable']:
            self.routes_always_check.append(route)
        else:
            for method in methods:
                if parameters:
                    self.routes_dynamic[url_hash(uri), method].append(route)
                else:
                    self.routes_static[uri, method] = route

    def remove(self, uri, clean_cache=True, methods=None, host=None):
        if methods is None:
            target_methods = DEFAULT_METHODS
        else:
            target_methods = [method.upper() for method in methods]

        if host is not None:
            uri = host + uri

        routes = {}
        for method in target_methods:
            try:
                routes[method] = self.routes_all.pop((uri, method))
            except KeyError:
                if methods is not None:
                    raise RouteDoesNotExist(
                        "Route was not registered: {} [{}]".format(uri, method))
        if not routes:
            raise RouteDoesNotExist("Route was not registered: {}".format(uri))

        deleted_methods = []
        deleted_routes = []
        for method, route in routes.items():
            if route in deleted_routes:
                deleted_methods.append(method)
            elif route in self.routes_always_check:
                self.routes_always_check.remove(route)
                deleted_methods.append(method)
                deleted_routes.append(route)
            elif (url_hash(uri), method) in self.routes_dynamic \
                    and route in self.routes_dynamic[url_hash(uri), method]:
                self.routes_dynamic[url_hash(uri), method].remove(route)
                deleted_methods.append(method)

        for method in routes:
            if method in deleted_methods:
                continue
            self.routes_static.pop((uri, method))

        if clean_cache:
            self._get.cache_clear()

    def get(self, request):
        """
        Gets a request handler based on the URL of the request, or raises an
        error
        :param request: Request object
        :return: handler, arguments, keyword arguments
        """
        if self.hosts is None:
            return self._get(request.url, request.method, '')
        else:
            return self._get(request.url, request.method,
                             request.headers.get("Host", ''))

    @lru_cache(maxsize=Config.ROUTER_CACHE_SIZE)
    def _get(self, url, method, host):
        """
        Gets a request handler based on the URL of the request, or raises an
        error.  Internal method for caching.
        :param url: Request URL
        :param method: Request method
        :return: handler, arguments, keyword arguments
        """
        url = host + url
        # Check against known static routes
        route = self.routes_static.get((url, method))
        if route:
            match = route.pattern.match(url)
        else:
            # Move on to testing all regex routes
            for route in self.routes_dynamic[url_hash(url), method]:
                match = route.pattern.match(url)
                if match:
                    break
            else:
                # Lastly, check against all regex routes that cannot be hashed
                for route in self.routes_always_check:
                    match = route.pattern.match(url)
                    if match:
                        break
                else:
                    raise NotFound('Requested URL {} not found'.format(url))

        if route.methods and method not in route.methods:
            raise InvalidUsage(
                'Method {} not allowed for URL {}'.format(
                    method, url), status_code=405)

        kwargs = {p.name: p.cast(value)
                  for value, p
                  in zip(match.groups(1), route.parameters)}
        return route.handler, [], kwargs
