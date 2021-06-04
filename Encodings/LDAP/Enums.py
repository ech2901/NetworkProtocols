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


class ResultCode(BaseEnum):
    Success = 0
    Operations_Error = 1
    Protocol_Error = 2
    Time_Limit_Exceeded = 3
    Size_Limit_Exceeded = 4
    Compare_False = 5
    Compare_True = 6
    Auth_Methods_Not_Supported = 7
    Stronger_Auth_Required = 8
    # 9 is reserved
    Referral = 10
    Admin_Limit_Exceeded = 11
    Unavailable_Critical_Extension = 12
    Confidentiality_Required = 13
    SASL_Bind_In_Progress = 14
    # 15 never defined
    No_Such_Attribute = 16
    Undefined_Attribute_Type = 17
    Inappropriate_Matching = 18
    Contraint_Violation = 19
    Attribute_Or_Value_Exists = 20
    Invalid_Attribute_Syntax = 21
    # 21 through 31 unused currently
    No_Such_Object = 32
    Alias_Problem = 33
    Invalid_DN_Syntax = 34
    # 35 reserved for undefined isLeaf
    ALias_Dereferencing_Problem = 36
    # 37 through 47 unused
    Inappropriate_Authentication = 48
    Invalid_Credentials = 49
    Insufficient_Access_Rights = 50
    Busy = 51
    Unavailable = 52
    Unwilling_To_Perform = 53
    Loop_Detect = 54
    # 55 through 63 unused
    Naming_Violation = 64
    Object_Class_Violation = 65
    Not_Allowed_On_Non_Leaf = 66
    Not_Allowed_On_RDN = 67
    Entry_Already_Exists = 68
    Object_Class_Mods_Prohibited = 69
    # 70 reserved for CLDAP
    Affects_Multiple_DSAs = 71
    # 72 through 79 unused
    Other = 80
