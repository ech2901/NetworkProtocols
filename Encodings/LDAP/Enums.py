from Encodings.ASN1 import BaseTag, IdentityClass
from Encodings.BaseEnum import BaseEnum


class LDAPTags(BaseTag):
    __id_class__ = IdentityClass.Application

    Bind_Request = 0
    Bind_Response = 1
    Unbind_Request = 2
    Search_Request = 3
    Search_Result_Entry = 4
    Search_Result_Done = 5
    Modify_Request = 6
    Modify_Response = 7
    Add_Request = 8
    Add_Response = 9
    Del_Request = 10
    Del_Response = 11
    Modify_DN_Request = 12
    Modify_DN_Response = 13
    Compare_Request = 14
    Compare_Response = 15
    Abandon_Request = 16
    Search_Result_Reference = 17
    Extended_Request = 18
    Extended_Response = 19
    Intermediate_Response = 20


class Scopes(BaseEnum):
    Base_Object = 0
    Single_Level = 1
    Whole_Subtree = 2


class DerefAliases(BaseEnum):
    Never_Deref_Aliases = 0
    Deref_In_Searching = 1
    Deref_Finding_Base_Object = 2
    Deref_Always = 3


class FilterChoice(BaseEnum):
    AND = 0
    OR = 1
    NOT = 2
    Equality_Match = 3
    Substrings = 4
    Greater_Or_Equal = 5
    Less_Or_Equal = 6
    Present = 7
    Approx_Match = 8
    Extensible_Match = 9


class Substring(BaseEnum):
    Initial = 0
    Any = 1
    Final = 2


class MatchingRuleAssertion(BaseEnum):
    Matching_Rule = 1
    Type = 2
    Match_Value = 3
    DN_Attributes = 4
