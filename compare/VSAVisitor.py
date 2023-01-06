# Generated from VSA.g4 by ANTLR 4.9.1
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .VSAParser import VSAParser
else:
    from VSAParser import VSAParser

# This class defines a complete generic visitor for a parse tree produced by VSAParser.

class VSAVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by VSAParser#expr_.
    def visitExpr_(self, ctx:VSAParser.Expr_Context):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by VSAParser#function.
    def visitFunction(self, ctx:VSAParser.FunctionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by VSAParser#expression.
    def visitExpression(self, ctx:VSAParser.ExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by VSAParser#atom.
    def visitAtom(self, ctx:VSAParser.AtomContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by VSAParser#scientific.
    def visitScientific(self, ctx:VSAParser.ScientificContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by VSAParser#variable.
    def visitVariable(self, ctx:VSAParser.VariableContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by VSAParser#binop.
    def visitBinop(self, ctx:VSAParser.BinopContext):
        return self.visitChildren(ctx)



del VSAParser