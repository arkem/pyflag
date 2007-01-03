""" This is a parser for the table search widget. The parser
implements a simple language for structured queries depending on the
type of the columns presented.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

def eval_expression(elements, name, operator, arg):
#    print "Evaluating %s.%s(%r)" % (name,operator,arg)
    ## Try and find the element with the specified name:
    element = None
    for e in elements:
        if e.name == name:
            element = e
            break
    
    if not element:
        raise RuntimeError("Column %s not known" % column)

    ## Use the element to parse:
    return element.parse(name, operator, arg)


# Begin -- grammar generated by Yapps
import sys, re
from yapps import runtime

class SearchParserScanner(runtime.Scanner):
    patterns = [
        ("'\\\\)'", re.compile('\\)')),
        ("'\\\\('", re.compile('\\(')),
        ('[ \r\t\n]+', re.compile('[ \r\t\n]+')),
        ('END', re.compile('$')),
        ('STR', re.compile('"([^\\\\"]+|\\\\.)*"')),
        ('STR2', re.compile("'([^\\\\']+|\\\\.)*'")),
        ('WORD', re.compile('[-:+*/!@$%^&=\\<\\>.a-zA-Z0-9_]+')),
        ('LOGICAL_OPERATOR', re.compile('(and|or)')),
    ]
    def __init__(self, str,*args,**kw):
        runtime.Scanner.__init__(self,None,{'[ \r\t\n]+':None,},str,*args,**kw)

class SearchParser(runtime.Parser):
    Context = runtime.Context
    def goal(self, types, _parent=None):
        _context = self.Context(_parent, self._scanner, 'goal', [types])
        clause = self.clause(types, _context)
        END = self._scan('END', context=_context)
        return clause

    def clause(self, types, _parent=None):
        _context = self.Context(_parent, self._scanner, 'clause', [types])
        expr = self.expr(types, _context)
        result = expr
        while self._peek('LOGICAL_OPERATOR', 'END', "'\\\\)'", context=_context) == 'LOGICAL_OPERATOR':
            LOGICAL_OPERATOR = self._scan('LOGICAL_OPERATOR', context=_context)
            logical_operator = LOGICAL_OPERATOR
            expr = self.expr(types, _context)
            result = "%s %s %s" % (result, logical_operator, expr)
        return result

    def term(self, _parent=None):
        _context = self.Context(_parent, self._scanner, 'term', [])
        _token = self._peek('STR', 'STR2', 'WORD', context=_context)
        if _token == 'STR':
            STR = self._scan('STR', context=_context)
            return eval(STR)
        elif _token == 'STR2':
            STR2 = self._scan('STR2', context=_context)
            return eval(STR2)
        else: # == 'WORD'
            WORD = self._scan('WORD', context=_context)
            return WORD

    def expr(self, types, _parent=None):
        _context = self.Context(_parent, self._scanner, 'expr', [types])
        _token = self._peek('STR', 'STR2', 'WORD', "'\\\\('", context=_context)
        if _token != "'\\\\('":
            term = self.term(_context)
            column = term
            WORD = self._scan('WORD', context=_context)
            operator = WORD
            term = self.term(_context)
            return  eval_expression(types, column,operator,term)
        else: # == "'\\\\('"
            self._scan("'\\\\('", context=_context)
            clause = self.clause(types, _context)
            self._scan("'\\\\)'", context=_context)
            return "( %s )" % clause


def parse(rule, text):
    P = SearchParser(SearchParserScanner(text))
    return runtime.wrap_error_reporter(P, rule)

# End -- grammar generated by Yapps



def parse_to_sql(text, types):
    P = SearchParser(SearchParserScanner(text))
    return runtime.wrap_error_reporter(P, 'goal', types)

if __name__=='__main__':
    import pyflag.TableObj as TableObj
    
    types = [ TableObj.TimestampType(name='Timestamp'),
              TableObj.IPType(name='IP Address')]

    test = 'Timestamp < "2006-10-01 \\\"10:10:00\\\"" or (Timestamp before \'2006-11-01 "10:10:00"\' and  "IP Address" netmask "192.168.1.1/24") or "IP Address" = 192.168.1.1'
    print "Will test %s" % test
    print parse_to_sql(test,types)
