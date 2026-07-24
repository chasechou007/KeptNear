import Foundation
import Security

struct PasswordGeneratorOptions: Equatable {
    var length = 20
    var includeUppercase = true
    var includeLowercase = true
    var includeNumbers = true
    var includeSymbols = true
    var avoidAmbiguousCharacters = true

    var normalizedLength: Int {
        min(max(length, 8), 64)
    }

    var hasSelectedCharacterClass: Bool {
        !PasswordGenerator.alphabet(for: self).isEmpty
    }
}

enum PasswordGeneratorError: LocalizedError {
    case noCharacterClasses
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .noCharacterClasses:
            return "Select at least one password character class"
        case let .randomFailure(status):
            return "Password generation failed with status \(status)"
        }
    }
}

struct PasswordGenerator {
    static let reducedUppercaseAlphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")
    static let reducedLowercaseAlphabet = Array("abcdefghijkmnopqrstuvwxyz")
    static let reducedNumberAlphabet = Array("23456789")
    static let fullUppercaseAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    static let fullLowercaseAlphabet = Array("abcdefghijklmnopqrstuvwxyz")
    static let fullNumberAlphabet = Array("0123456789")
    static let symbolAlphabet = Array("!@#$%^&*-_=+?")

    private let randomByte: () throws -> UInt8

    init(randomByte: @escaping () throws -> UInt8 = PasswordGenerator.secureRandomByte) {
        self.randomByte = randomByte
    }

    func generate(options: PasswordGeneratorOptions) throws -> String {
        let characterClasses = Self.characterClasses(for: options)
        guard !characterClasses.isEmpty else {
            throw PasswordGeneratorError.noCharacterClasses
        }

        let alphabet = characterClasses.flatMap(\.characters)
        var result: [Character] = []
        result.reserveCapacity(options.normalizedLength)

        for characterClass in characterClasses where result.count < options.normalizedLength {
            result.append(try randomCharacter(from: characterClass.characters))
        }

        while result.count < options.normalizedLength {
            result.append(try randomCharacter(from: alphabet))
        }

        try shuffle(&result)
        return String(result)
    }

    static func alphabet(for options: PasswordGeneratorOptions) -> [Character] {
        characterClasses(for: options).flatMap(\.characters)
    }

    private static func characterClasses(for options: PasswordGeneratorOptions) -> [PasswordCharacterClass] {
        var characterClasses: [PasswordCharacterClass] = []
        if options.includeUppercase {
            characterClasses.append(PasswordCharacterClass(
                characters: options.avoidAmbiguousCharacters ? reducedUppercaseAlphabet : fullUppercaseAlphabet
            ))
        }
        if options.includeLowercase {
            characterClasses.append(PasswordCharacterClass(
                characters: options.avoidAmbiguousCharacters ? reducedLowercaseAlphabet : fullLowercaseAlphabet
            ))
        }
        if options.includeNumbers {
            characterClasses.append(PasswordCharacterClass(
                characters: options.avoidAmbiguousCharacters ? reducedNumberAlphabet : fullNumberAlphabet
            ))
        }
        if options.includeSymbols {
            characterClasses.append(PasswordCharacterClass(characters: symbolAlphabet))
        }
        return characterClasses
    }

    private func randomCharacter(from alphabet: [Character]) throws -> Character {
        alphabet[try randomIndex(upperBound: alphabet.count)]
    }

    private func randomIndex(upperBound: Int) throws -> Int {
        let bucketCount = Int(UInt8.max) + 1
        let limit = bucketCount - (bucketCount % upperBound)
        while true {
            let byte = Int(try randomByte())
            guard byte < limit else { continue }
            return byte % upperBound
        }
    }

    private func shuffle(_ characters: inout [Character]) throws {
        guard characters.count > 1 else { return }
        for index in stride(from: characters.count - 1, through: 1, by: -1) {
            let swapIndex = try randomIndex(upperBound: index + 1)
            characters.swapAt(index, swapIndex)
        }
    }

    private static func secureRandomByte() throws -> UInt8 {
        var byte: UInt8 = 0
        let status = SecRandomCopyBytes(kSecRandomDefault, 1, &byte)
        guard status == errSecSuccess else {
            throw PasswordGeneratorError.randomFailure(status)
        }
        return byte
    }
}

private struct PasswordCharacterClass {
    let characters: [Character]
}

struct PasswordGeneratorPreferences {
    static let lengthKey = "passwordGenerator.length"
    static let includeUppercaseKey = "passwordGenerator.includeUppercase"
    static let includeLowercaseKey = "passwordGenerator.includeLowercase"
    static let includeNumbersKey = "passwordGenerator.includeNumbers"
    static let includeSymbolsKey = "passwordGenerator.includeSymbols"
    static let avoidAmbiguousCharactersKey = "passwordGenerator.avoidAmbiguousCharacters"
    static let allKeys = [
        lengthKey,
        includeUppercaseKey,
        includeLowercaseKey,
        includeNumbersKey,
        includeSymbolsKey,
        avoidAmbiguousCharactersKey
    ]

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func loadOptions() -> PasswordGeneratorOptions {
        let defaultsOptions = PasswordGeneratorOptions()
        return PasswordGeneratorOptions(
            length: loadLength(defaultValue: defaultsOptions.length),
            includeUppercase: loadBool(Self.includeUppercaseKey, defaultValue: defaultsOptions.includeUppercase),
            includeLowercase: loadBool(Self.includeLowercaseKey, defaultValue: defaultsOptions.includeLowercase),
            includeNumbers: loadBool(Self.includeNumbersKey, defaultValue: defaultsOptions.includeNumbers),
            includeSymbols: loadBool(Self.includeSymbolsKey, defaultValue: defaultsOptions.includeSymbols),
            avoidAmbiguousCharacters: loadBool(Self.avoidAmbiguousCharactersKey, defaultValue: defaultsOptions.avoidAmbiguousCharacters)
        )
    }

    func saveOptions(_ options: PasswordGeneratorOptions) {
        defaults.set(options.normalizedLength, forKey: Self.lengthKey)
        defaults.set(options.includeUppercase, forKey: Self.includeUppercaseKey)
        defaults.set(options.includeLowercase, forKey: Self.includeLowercaseKey)
        defaults.set(options.includeNumbers, forKey: Self.includeNumbersKey)
        defaults.set(options.includeSymbols, forKey: Self.includeSymbolsKey)
        defaults.set(options.avoidAmbiguousCharacters, forKey: Self.avoidAmbiguousCharactersKey)
    }

    private func loadLength(defaultValue: Int) -> Int {
        guard defaults.object(forKey: Self.lengthKey) != nil else { return defaultValue }
        return min(max(defaults.integer(forKey: Self.lengthKey), 8), 64)
    }

    private func loadBool(_ key: String, defaultValue: Bool) -> Bool {
        guard defaults.object(forKey: key) != nil else { return defaultValue }
        return defaults.bool(forKey: key)
    }
}
