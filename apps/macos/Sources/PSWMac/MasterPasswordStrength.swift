import Foundation

enum MasterPasswordStrengthLevel: Int, Equatable, Comparable {
    case empty
    case weak
    case fair
    case strong
    case veryStrong

    static func < (lhs: MasterPasswordStrengthLevel, rhs: MasterPasswordStrengthLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

struct MasterPasswordStrength: Equatable {
    static let minimumLength = 12

    let level: MasterPasswordStrengthLevel
    let characterCount: Int
    let characterClassCount: Int
    let containsCommonWeakTerm: Bool

    static func evaluate(
        _ password: String,
        minimumLength: Int = MasterPasswordStrength.minimumLength
    ) -> MasterPasswordStrength {
        let characterCount = password.count
        let characterClassCount = Self.characterClassCount(password)
        let containsCommonWeakTerm = Self.containsCommonWeakTerm(password)

        guard characterCount > 0 else {
            return MasterPasswordStrength(
                level: .empty,
                characterCount: characterCount,
                characterClassCount: characterClassCount,
                containsCommonWeakTerm: containsCommonWeakTerm
            )
        }

        var score = 0
        if characterCount >= minimumLength { score += 1 }
        if characterCount >= 16 { score += 1 }
        if characterCount >= 20 { score += 1 }
        if characterCount >= 24 { score += 1 }

        score += min(max(characterClassCount - 1, 0), 3)

        let uniqueCharacterCount = Set(password).count
        if uniqueCharacterCount >= min(8, characterCount) {
            score += 1
        }
        if uniqueCharacterCount <= 3 {
            score -= 2
        }
        if Self.hasLongRepeatedRun(password) {
            score -= 1
        }
        if containsCommonWeakTerm {
            score -= 2
        }

        let level: MasterPasswordStrengthLevel
        if characterCount < minimumLength {
            level = .weak
        } else if score >= 7 {
            level = .veryStrong
        } else if score >= 5 {
            level = .strong
        } else if score >= 3 {
            level = .fair
        } else {
            level = .weak
        }

        return MasterPasswordStrength(
            level: level,
            characterCount: characterCount,
            characterClassCount: characterClassCount,
            containsCommonWeakTerm: containsCommonWeakTerm
        )
    }

    private static func characterClassCount(_ password: String) -> Int {
        var classes = Set<String>()
        for scalar in password.unicodeScalars {
            if CharacterSet.lowercaseLetters.contains(scalar) {
                classes.insert("lowercase")
            } else if CharacterSet.uppercaseLetters.contains(scalar) {
                classes.insert("uppercase")
            } else if CharacterSet.decimalDigits.contains(scalar) {
                classes.insert("digit")
            } else {
                classes.insert("symbol")
            }
        }
        return classes.count
    }

    private static func containsCommonWeakTerm(_ password: String) -> Bool {
        let normalized = password.lowercased()
        let commonTerms = [
            "password",
            "qwerty",
            "letmein",
            "admin",
            "welcome",
            "iloveyou",
            "123456"
        ]
        return commonTerms.contains { normalized.contains($0) }
    }

    private static func hasLongRepeatedRun(_ password: String) -> Bool {
        var previous: Character?
        var runLength = 0
        for character in password {
            if character == previous {
                runLength += 1
            } else {
                previous = character
                runLength = 1
            }
            if runLength >= 4 {
                return true
            }
        }
        return false
    }
}
