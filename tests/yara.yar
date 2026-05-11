/* TEST CASE 1: Standard valid rule with metadata and tags
*/
rule Valid_Rule_01 : Trojan Tag_Test {
    meta:
        author = "RuleCast_Tester"
        description = "A standard rule to check metadata parsing. Reference: CVE-2023-1234"
        version = "1.1"
        id = "uuid-1234-5678"
    strings:
        $a = "malware_signature_01"
    condition:
        $a
}

// TEST CASE 2: Two rules stuck together (No newline) to test split_rules
rule Rule_Stuck_A{condition:true}rule Rule_Stuck_B{condition:true}

/*
   TEST CASE 3: Missing Module (Should trigger your auto-import "pe")
*/
rule Missing_Import_PE {
    meta:
        description = "This rule uses PE module without importing it."
    condition:
        pe.is_dll() and pe.number_of_sections > 3
}

/*
   TEST CASE 4: Nested braces in strings (The "Splitter Killer")
   This tests if your brace counter is fooled by strings or comments.
*/
rule Complex_Braces_Strings {
    meta:
        info = "Braces in strings: } } } and comments /* } */"
    strings:
        $regex = /\{[a-z]\}[\/]/
        $hex = { EB 04 [2-5] 90 } 
    condition:
        $regex and $hex
}

/*
   TEST CASE 5: Invalid Syntax (Should fail validation)
*/
rule This_Is_Broken {
    condition:
        $invalid_variable_without_definition
}

/*
   TEST CASE 6: Missing Module (Math)
*/
rule Missing_Import_Math {
    meta:
        description = "Testing CVE-2021-9999 detection"
    condition:
        math.entropy(0, 100) > 7.0
}

# Ce texte ici est invalide et ne doit pas être reconnu comme une règle
Ce n'est pas une règle YARA, c'est juste du bruit pour tester le can_handle.