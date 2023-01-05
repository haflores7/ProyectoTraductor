from optparse import OptionParser
from sys import stdout, exit as sys_exit


DEBUG = True  # TODO:.


def debug_print(func):
   
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        if DEBUG:
            stdout.write('\n++Call {} with A:{} K:{}\n++got back {}\n'.format(
                func.__name__, args, kwargs, ret))
            stdout.flush()
        return ret
    return wrapper

def sql_to_spec(query):
   
    @debug_print
    def fix_token_list(in_list):
       
        if isinstance(in_list, list) and len(in_list) == 1 and \
           isinstance(in_list[0], list):
            return fix_token_list(in_list[0])
        else:
            return [item for item in in_list]

    @debug_print
    def select_count_func(tokens=None):
        return full_select_func(tokens, 'count')

    @debug_print
    def select_distinct_func(tokens=None):
        return full_select_func(tokens, 'distinct')

    @debug_print
    def select_func(tokens=None):
        return full_select_func(tokens, 'select')

    def full_select_func(tokens=None, method='select'):
        
        action = {'distinct': 'distinct',
                  'count': 'count'
                  }.get(method, 'find')
        if tokens is None:
            return
        ret = {action: True,
               'fields': {item: 1 for item in fix_token_list(tokens.asList())}}
        if ret['fields'].get('id'):  
            
            del(ret['fields']['id'])
        else:
            ret['fields']['_id'] = 0
        if "*" in ret['fields'].keys():
            ret['fields'] = {}
        return ret

    @debug_print
    def where_func(tokens=None):
        
        if tokens is None:
            return

        tokens = fix_token_list(tokens.asList()) + [None, None, None]
        cond = {'!=': '$d',
                '>': '$ma',
                '>=': '$mai',
                '<': '$me',
                '<=': '$mei',
                'like': '$lik'}.get(tokens[1])

        find_value = tokens[2].strip('"').strip("'")
        if cond == '$regex':
            if find_value[0] != '%':
                find_value = "^" + find_value
            if find_value[-1] != '%':
                find_value = find_value + "$"
            find_value = find_value.strip("%")

        if cond is None:
            expr = {tokens[0]: find_value}
        else:
            expr = {tokens[0]: {cond: find_value}}

        return expr

    @debug_print
    def combine(tokens=None):
        if tokens:
            tokens = fix_token_list(tokens.asList())
            if len(tokens) == 1:
                return tokens
            else:
                return {'${}'.format(tokens[1]): [tokens[0], tokens[2]]}


    # TODO: Reduce list of imported functions.
    from pyparsing import (Word, alphas, CaselessKeyword, Group, Optional, ZeroOrMore,
                           Forward, Suppress, alphanums, OneOrMore, quotedString,
                           Combine, Keyword, Literal, replaceWith, oneOf, nums,
                           removeQuotes, QuotedString, Dict)

    LPAREN, RPAREN = map(Suppress, "()")
    EXPLAIN = CaselessKeyword('EXPLAIN'
                              ).setParseAction(lambda t: {'explain': True})
    SELECT = Suppress(CaselessKeyword('SELECT'))
    WHERE = Suppress(CaselessKeyword('WHERE'))
    FROM = Suppress(CaselessKeyword('FROM'))
    CONDITIONS = oneOf("= != < > <= >= like", caseless=True)
    #CONDITIONS = (Keyword("=") | Keyword("!=") |
    #              Keyword("<") | Keyword(">") |
    #              Keyword("<=") | Keyword(">="))
    AND = CaselessKeyword('and')
    OR = CaselessKeyword('or')

    word_match = Word(alphanums + "._") | quotedString
    number = Word(nums)
    statement = Group(word_match + CONDITIONS + word_match
                      ).setParseAction(where_func)
    select_fields = Group(SELECT + (word_match | Keyword("*")) +
                          ZeroOrMore(Suppress(",") +
                                    (word_match | Keyword("*")))
                          ).setParseAction(select_func)

    select_distinct = (SELECT + Suppress(CaselessKeyword('DISTINCT')) + LPAREN
                            + (word_match | Keyword("*"))
                               + ZeroOrMore(Suppress(",")
                               + (word_match | Keyword("*")))
                            + Suppress(RPAREN)).setParseAction(select_distinct_func)

    select_count = (SELECT + Suppress(CaselessKeyword('COUNT')) + LPAREN
                            + (word_match | Keyword("*"))
                               + ZeroOrMore(Suppress(",")
                               + (word_match | Keyword("*")))
                            + Suppress(RPAREN)).setParseAction(select_count_func)
    LIMIT = (Suppress(CaselessKeyword('LIMIT')) + word_match).setParseAction(lambda t: {'limit': t[0]})
    SKIP = (Suppress(CaselessKeyword('SKIP')) + word_match).setParseAction(lambda t: {'skip': t[0]})
    from_table = (FROM + word_match).setParseAction(
        lambda t: {'collection': t.asList()[0]})
    

    operation_term = (select_distinct | select_count | select_fields)   
    expr = Forward()
    atom = statement | (LPAREN + expr + RPAREN)
    and_term = (OneOrMore(atom) + ZeroOrMore(AND + atom)
                ).setParseAction(combine)
    or_term = (and_term + ZeroOrMore(OR + and_term)).setParseAction(combine)

    where_clause = (WHERE + or_term
                    ).setParseAction(lambda t: {'spec': t[0]})
    list_term = Optional(EXPLAIN) + operation_term + from_table + \
                Optional(where_clause) + Optional(LIMIT) + Optional(SKIP)
    expr << list_term

    ret = expr.parseString(query.strip())
    query_dict = {}
    _ = map(query_dict.update, ret)
    return query_dict


def spec_str(spec):
    

    if spec is None:
        return "{}"
    if isinstance(spec, list):
        out_str = "[" + ', '.join([spec_str(x) for x in spec]) + "]"
    elif isinstance(spec, dict):
        out_str = "{" + ', '.join(["{}:{}".format(x, spec_str(spec[x])
                                                  ) for x in sorted(spec)]) + "}"
    elif spec and isinstance(spec, str) and not spec.isdigit():
        out_str = "'" + spec + "'"
    else:
        out_str = spec

    return out_str

@debug_print
def create_mongo_shell_query(query_dict):
    
    if not query_dict.get('collection'):
        return
    shell_query = "db." + query_dict.get('collection') + "."

    if query_dict.get('find'):
        shell_query += 'find({}, {})'.format(spec_str(query_dict.get('spec')),
                                             spec_str(query_dict.get('fields')))
    elif query_dict.get('distinct'):
        shell_query += 'distinct({})'.format(spec_str(",".join(
            [k for k in query_dict.get('fields').keys() if query_dict['fields'][k]])))
    elif query_dict.get('count'):
        shell_query += 'count({})'.format(spec_str(query_dict.get('spec')))
    if query_dict.get('skip'):
        shell_query += ".skip({})".format(query_dict.get('skip'))

    if query_dict.get('limit'):
        shell_query += ".limit({})".format(query_dict.get('limit'))

    if query_dict.get('explain'):
        shell_query += ".explain()"

    return shell_query


def execute_query(spec, connection_string=None):
   
    if connection_string is None:
        connection_string = "mongo://localhost:27017/test"
    if connection_string:
        print "Conectando a", connection_string
    print "No implentado "
    return []

if __name__ == "__main__":
    usage = "usage: %prog [options] select"
    parser = OptionParser(usage=usage)
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="No imprime las especificaciones")
    parser.add_option("-m", "--mongo",
                      dest="mongo_server",
                      default=None,
                      help="No implementado")
    parser.add_option("-n", "--no_db",
                      action="store_true", dest="no_db", default=False,
                      help="No ejecuta la consulta para mongodb")
    parser.add_option("-j", "--json",
                      action="store_true", dest="format_json", default=False,
                      help="No implementado devolviendo datos como JSON")
    parser.add_option("-s", "--shell",  
                      action="store_true", dest="shell", default=False,
                      help="No implementado como consulta sql")

    (options, args) = parser.parse_args()
    
    if not args:
        parser.print_help()
        sys_exit(1)

    query = ' '.join([arg if ' ' not in arg else "'" + arg + "'" for arg in args])
    if query[0] in ['"', "'"] and query[0] == query[-1]:
        query = query.strip(query[0])
    if not options.verbose:
        DEBUG = False  
    query_dict = sql_to_spec(query)
    if options.no_db or options.verbose:
        print "La consulta SQL: ", query
        print "La cosulta MongoDB: ", create_mongo_shell_query(query_dict)

    elif not options.no_db:
        result = execute_query(query_dict, options.mongo_server)
        print result
        
