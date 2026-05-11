// ============================================================
// RULECAST — YARA TEST SUITE
//
// EXPECTED RESULTS (update when adding rules):
//   Total rules  : 99
//   Valid        : 74
//   Invalid      : 20
//   Incomplete   : 5
//
// Run with: python3 main.py test → choose yara → file → 1
// ============================================================


// ============================================================
// VALID RULES — BASIC
// ============================================================

rule Valid_Minimal {
    condition:
        true
}

rule Valid_False_Condition {
    condition:
        false
}


// ============================================================
// VALID RULES — STRINGS
// ============================================================

rule Valid_String_Simple {
    strings:
        $a = "hello world"
    condition:
        $a
}

rule Valid_String_Hex {
    strings:
        $hex = { DE AD BE EF CA FE BA BE }
    condition:
        $hex
}

rule Valid_String_Regex {
    strings:
        $re = /malware[0-9]+\.exe/i
    condition:
        $re
}

rule Valid_String_Wide {
    strings:
        $wide = "malware" wide
    condition:
        $wide
}

rule Valid_String_Ascii_Wide {
    strings:
        $aw = "evil" ascii wide
    condition:
        $aw
}

rule Valid_String_Nocase {
    strings:
        $nc = "Evil" nocase
    condition:
        $nc
}

rule Valid_String_Fullword {
    strings:
        $fw = "cmd.exe" fullword
    condition:
        $fw
}

rule Valid_Multiple_Strings {
    strings:
        $a = "string_one"
        $b = "string_two"
        $c = "string_three"
    condition:
        $a or $b or $c
}

rule Valid_All_Of {
    strings:
        $a = "one"
        $b = "two"
        $c = "three"
    condition:
        all of them
}

rule Valid_Any_Of {
    strings:
        $a = "one"
        $b = "two"
    condition:
        any of them
}

rule Valid_None_Of {
    strings:
        $a = "evil"
        $b = "malware"
    condition:
        none of them
}

rule Valid_Count {
    strings:
        $a = "bad"
    condition:
        #a > 3
}

rule Valid_At_Offset {
    strings:
        $a = "MZ"
    condition:
        $a at 0
}

rule Valid_In_Range {
    strings:
        $a = "PE"
    condition:
        $a in (0..100)
}

rule Valid_Xor_String {
    strings:
        $x = "malware" xor
    condition:
        $x
}

rule Valid_Xor_Range {
    strings:
        $x = "virus" xor(1-255)
    condition:
        $x
}

rule Valid_Escaped_Quote {
    strings:
        $a = "he said \"hello\""
    condition:
        $a
}

rule Valid_Backslash {
    strings:
        $a = "C:\\Windows\\System32"
    condition:
        $a
}

rule Valid_Brace_In_String {
    strings:
        $a = "function() { return { key: 'value' }; }"
    condition:
        $a
}


// ============================================================
// VALID RULES — HEX
// ============================================================

rule Valid_Hex_Wildcard {
    strings:
        $h = { 4D 5A ?? ?? ?? ?? 00 }
    condition:
        $h
}

rule Valid_Hex_Jump {
    strings:
        $h = { DE AD [2-4] BE EF }
    condition:
        $h
}

rule Valid_Hex_Alternatives {
    strings:
        $h = { (DE | AD) BE EF }
    condition:
        $h
}

rule Valid_Long_Hex {
    strings:
        $h = {
            4D 5A 90 00 03 00 00 00
            04 00 00 00 FF FF 00 00
            B8 00 00 00 00 00 00 00
            40 00 00 00 00 00 00 00
        }
    condition:
        $h at 0
}

rule Valid_Hex_All_Nibbles {
    strings:
        $h = { 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF }
    condition:
        $h
}

rule Valid_Curly_In_Regex {
    strings:
        $r = /a{3,5}b{2}/
    condition:
        $r
}


// ============================================================
// VALID RULES — METADATA
// ============================================================

rule Valid_With_Meta {
    meta:
        author = "test"
        description = "A test rule"
        version = "1.0"
    condition:
        true
}

rule Valid_Meta_All_Types {
    meta:
        author = "Jane Doe"
        description = "Detects CVE-2021-44228 log4shell"
        reference = "https://example.com"
        date = "2024-01-01"
        version = "2.3"
        severity = "high"
        id = "550e8400-e29b-41d4-a716-446655440000"
    condition:
        true
}

rule Valid_Only_Meta {
    meta:
        author = "ghost"
        description = "no strings needed"
    condition:
        filesize > 0
}

rule Valid_With_Comments {
    meta:
        author = "tester"
    strings:
        $a = "evil"
    condition:
        $a
}


// ============================================================
// VALID RULES — TAGS
// ============================================================

rule Valid_With_Tags : malware ransomware {
    condition:
        true
}

rule Valid_Tags_And_Meta : apt trojan {
    meta:
        author = "tester"
    condition:
        false
}

rule Valid_Many_Tags : malware trojan apt ransomware stealer dropper loader {
    condition:
        true
}


// ============================================================
// VALID RULES — MODIFIERS
// ============================================================

global rule Valid_Global {
    condition:
        true
}

private rule Valid_Private {
    condition:
        true
}

global private rule Valid_Global_Private {
    condition:
        true
}


// ============================================================
// VALID RULES — FILESIZE / CONDITIONS
// ============================================================

rule Valid_Filesize_Less {
    condition:
        filesize < 1MB
}

rule Valid_Filesize_Greater {
    condition:
        filesize > 500KB
}

rule Valid_Filesize_Range {
    condition:
        filesize >= 100 and filesize <= 10MB
}

rule Valid_Arithmetic_Condition {
    condition:
        (filesize % 512) == 0
}

rule Valid_And_Or_Not {
    strings:
        $a = "foo"
        $b = "bar"
    condition:
        ($a and not $b) or (not $a and $b)
}

rule Valid_Complex_Condition {
    strings:
        $a = "aaa"
        $b = "bbb"
        $c = "ccc"
    condition:
        (#a > 1) and ($b or $c) and filesize < 5MB
}

rule Valid_Of_Wildcard {
    strings:
        $prefix_one = "aaa"
        $prefix_two = "bbb"
        $prefix_three = "ccc"
    condition:
        2 of ($prefix_*)
}

rule Valid_N_Of_Them {
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
    condition:
        2 of them
}

rule Valid_Offset_Condition {
    strings:
        $a = "EICAR"
    condition:
        $a in (0..filesize)
}

rule Valid_Entrypoint {
    strings:
        $a = "payload"
    condition:
        $a at entrypoint
}

rule Valid_For_Loop {
    strings:
        $a = "loop_target"
    condition:
        for any i in (0..10) : ($a at i)
}


// ============================================================
// VALID RULES — PE MODULE
// ============================================================

import "pe"

rule Valid_PE_Is_PE {
    condition:
        pe.is_pe
}

rule Valid_PE_Machine_x86 {
    condition:
        pe.machine == pe.MACHINE_I386
}

rule Valid_PE_Machine_x64 {
    condition:
        pe.machine == pe.MACHINE_AMD64
}

rule Valid_PE_Number_Of_Sections {
    condition:
        pe.number_of_sections > 3
}

rule Valid_PE_Timestamp {
    condition:
        pe.timestamp > 0
}

rule Valid_PE_Imphash {
    condition:
        pe.imphash() != ""
}

rule Valid_PE_Has_Section_Text {
    condition:
        pe.sections[0].name == ".text"
}

rule Valid_PE_Imports_CreateFile {
    condition:
        pe.imports("kernel32.dll", "CreateFileA")
}

rule Valid_PE_Imports_VirtualAlloc {
    condition:
        pe.imports("kernel32.dll", "VirtualAlloc")
}

rule Valid_PE_Exports {
    condition:
        pe.number_of_exports > 0
}

rule Valid_PE_Characteristics_DLL {
    condition:
        pe.characteristics & pe.DLL
}

rule Valid_PE_Subsystem_GUI {
    condition:
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI
}

rule Valid_PE_Resources {
    condition:
        pe.number_of_resources > 0
}

rule Valid_PE_With_Strings_And_PE {
    strings:
        $mz = { 4D 5A }
        $sus = "VirtualAlloc"
    condition:
        $mz at 0 and $sus and pe.is_pe
}

rule Valid_PE_Complex {
    meta:
        author = "tester"
        description = "Complex PE rule combining multiple checks"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
    condition:
        pe.is_pe and
        pe.number_of_sections >= 2 and
        ($s1 or $s2) and
        filesize < 5MB
}


// ============================================================
// VALID RULES — SEQUENCES (stress test split_rules)
// ============================================================

rule Valid_SeqA {
    condition: true
}

rule Valid_SeqB {
    condition: true
}

rule Valid_SeqC {
    condition: true
}

rule Valid_SeqD : tag1 tag2 {
    meta:
        x = "y"
    strings:
        $s = "seq"
    condition:
        $s
}

rule Valid_SeqE {
    condition: false
}

rule Valid_NoGap_A {
    condition: true
}
rule Valid_NoGap_B {
    condition: true
}
rule Valid_NoGap_C {
    condition: true
}


// ============================================================
// VALID RULES — EDGE CASES
// ============================================================

rule Valid_Name_With_123_underscores___test {
    condition:
        true
}

rule Valid_This_Is_A_Very_Long_Rule_Name_That_Goes_On_And_On_And_On_Still_Going_Yes_Really {
    condition:
        true
}

rule Valid_With_Import_Math {
    strings:
        $data = { 00 01 02 03 }
    condition:
        $data and filesize > 0
}


// ============================================================
// INVALID RULES
// Expected to FAIL validation — 20 total
// ============================================================

// invalid_01: missing condition block
rule Invalid_No_Condition {
    strings:
        $a = "test"
}

// invalid_02: empty body
rule Invalid_Empty_Body {
}

// invalid_03: unterminated string
rule Invalid_Unterminated_String {
    strings:
        $a = "unterminated
    condition:
        $a
}

// invalid_04: unknown modifier
rule Invalid_Unknown_Modifier {
    strings:
        $a = "test" superfast
    condition:
        $a
}

// invalid_05: invalid hex chars
rule Invalid_Bad_Hex {
    strings:
        $h = { ZZ ZZ ZZ }
    condition:
        $h
}

// invalid_06+07: duplicate rule names
rule Invalid_Duplicate_Name {
    condition:
        true
}

rule Invalid_Duplicate_Name {
    condition:
        false
}

// invalid_08: undefined string reference
rule Invalid_Undefined_String {
    condition:
        $undefined_var
}

// invalid_09: double AND in condition
rule Invalid_Bad_Condition_Syntax {
    condition:
        true and and false
}

// invalid_10: bad filesize unit
rule Invalid_Bad_Unit {
    condition:
        filesize < 1GB_TYPO
}

// invalid_11: junk token at end of rule
rule Invalid_Junk_Token {
    strings:
        $a = "test"
    condition:
        $a
    XXXXX_NOT_VALID
}

// invalid_12: unterminated regex
rule Invalid_Unterminated_Regex {
    strings:
        $r = /open_regex
    condition:
        $r
}

// invalid_13: pe.machine comparison with garbage value
rule Invalid_PE_Bad_Comparison {
    condition:
        pe.machine == 0xDEAD_BEEF_NOT_A_VALID_CONSTANT
}

// invalid_14: pe import wrong arg count
rule Invalid_PE_Import_Too_Many_Args {
    condition:
        pe.imports("kernel32.dll", "CreateFile", "extra_arg")
}

// invalid_15: condition references nonexistent section index
rule Invalid_PE_Section_Out_Of_Bounds_Syntax {
    condition:
        pe.sections[999999999999999].name == ".text"
}

// invalid_16: pe.is_pe used as string (wrong type)
rule Invalid_PE_Wrong_Type {
    strings:
        $a = pe.is_pe
    condition:
        $a
}

// invalid_17: missing import for pe module
rule Invalid_PE_No_Import {
    condition:
        pe.number_of_sections > 0 and nonexistent_pe_function()
}

// invalid_18: and without operands
rule Invalid_Bare_And {
    condition:
        and
}

// invalid_19: string defined but condition empty
rule Invalid_Empty_Condition_Block {
    strings:
        $a = "test"
    condition:
}

// invalid_20: nested rule keyword inside condition (parser confusion)
rule Invalid_Nested_Rule_Keyword {
    condition:
        rule
}


// ============================================================
// TRUNCATED / INCOMPLETE RULES
// Expected to FAIL — no closing brace — 5 total
// ============================================================

rule Incomplete_No_Closing_Brace {
    condition:
        true

rule Incomplete_Strings_No_Close {
    strings:
        $a = "dangling"
    condition:
        $a

rule Incomplete_Only_Meta {
    meta:
        author = "nobody"

rule Incomplete_Mid_Strings {
    strings:
        $a = "first"
        $b = "second"

rule Incomplete_Empty {