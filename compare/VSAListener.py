# Generated from VSA.g4 by ANTLR 4.9.1
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .VSAParser import VSAParser
else:
    from VSAParser import VSAParser

# This class defines a complete listener for a parse tree produced by VSAParser.
class VSAListener(ParseTreeListener):

    # Enter a parse tree produced by VSAParser#expr_.
    def enterExpr_(self, ctx:VSAParser.Expr_Context):
        pass

    # Exit a parse tree produced by VSAParser#expr_.
    def exitExpr_(self, ctx:VSAParser.Expr_Context):
        pass


    # Enter a parse tree produced by VSAParser#function.
    def enterFunction(self, ctx:VSAParser.FunctionContext):
        pass

    # Exit a parse tree produced by VSAParser#function.
    def exitFunction(self, ctx:VSAParser.FunctionContext):
        pass


    # Enter a parse tree produced by VSAParser#expression.
    def enterExpression(self, ctx:VSAParser.ExpressionContext):
        pass

    # Exit a parse tree produced by VSAParser#expression.
    def exitExpression(self, ctx:VSAParser.ExpressionContext):
        pass


    # Enter a parse tree produced by VSAParser#atom.
    def enterAtom(self, ctx:VSAParser.AtomContext):
        pass

    # Exit a parse tree produced by VSAParser#atom.
    def exitAtom(self, ctx:VSAParser.AtomContext):
        pass


    # Enter a parse tree produced by VSAParser#scientific.
    def enterScientific(self, ctx:VSAParser.ScientificContext):
        pass

    # Exit a parse tree produced by VSAParser#scientific.
    def exitScientific(self, ctx:VSAParser.ScientificContext):
        pass


    # Enter a parse tree produced by VSAParser#variable.
    def enterVariable(self, ctx:VSAParser.VariableContext):
        pass

    # Exit a parse tree produced by VSAParser#variable.
    def exitVariable(self, ctx:VSAParser.VariableContext):
        pass


    # Enter a parse tree produced by VSAParser#binop.
    def enterBinop(self, ctx:VSAParser.BinopContext):
        pass

    # Exit a parse tree produced by VSAParser#binop.
    def exitBinop(self, ctx:VSAParser.BinopContext):
        pass



del VSAParser