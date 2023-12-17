using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("Choose a Cipher:");
        Console.WriteLine("1. Caesar Cipher");
        Console.WriteLine("2. Vigenere Cipher");
        

        Console.Write("Enter your choice (1 or 2): ");
        int choice = int.Parse(Console.ReadLine());
        

        switch (choice)
        {
            case 1:
                CaesarCipher();
                break;
            case 2:
                VigenereCipher();
                break;
            
            default:
                Console.WriteLine("Invalid choice. Please enter 1 or 2");
                break;
        }
    }

    static void CaesarCipher()
    {
        Console.WriteLine("\nCaesar Cipher");

        Console.Write("Enter the plaintext: ");
        string caesarPlaintext = Console.ReadLine().ToUpper();
        Console.Write("Enter the shift value: ");
        int caesarShift = int.Parse(Console.ReadLine());

        string caesarCiphertext = CaesarEncrypt(caesarPlaintext, caesarShift);
        string caesarDecryptedText = CaesarDecrypt(caesarCiphertext, caesarShift);

        Console.WriteLine($"Plaintext: {caesarPlaintext}");
        Console.WriteLine($"Encrypted Text: {caesarCiphertext}");
        Console.WriteLine($"Decrypted Text: {caesarDecryptedText}");
    }

    static void VigenereCipher()
    {
        Console.WriteLine("\nVigenere Cipher");

        Console.Write("Enter the plaintext: ");
        string vigenerePlaintext = Console.ReadLine().ToUpper();
        Console.Write("Enter the key: ");
        string vigenereKey = Console.ReadLine().ToUpper();

        string vigenereCiphertext = EncryptVigenere(vigenerePlaintext, vigenereKey);
        string vigenereDecryptedText = DecryptVigenere(vigenereCiphertext, vigenereKey);

        Console.WriteLine($"Plaintext: {vigenerePlaintext}");
        Console.WriteLine($"Key: {vigenereKey}");
        Console.WriteLine($"Encrypted Text: {vigenereCiphertext}");
        Console.WriteLine($"Decrypted Text: {vigenereDecryptedText}");
    }
    //_________________________________methods for encrypt and decrypt_________________________________

    //ceaser:

    static string CaesarEncrypt(string text, int shift)
    {
        char[] result = text.ToCharArray();

        for (int i = 0; i < result.Length; i++)
        {
            if (char.IsLetter(result[i]))
            {
                char baseChar = char.IsUpper(result[i]) ? 'A' : 'a';
                result[i] = (char)((result[i] - baseChar + shift) % 26 + baseChar);
            }
        }

        return new string(result);
    }

    static string CaesarDecrypt(string text, int shift)
    {
        return CaesarEncrypt(text, 26 - shift); // Decryption is essentially encryption with the opposite shift
    }

    //veginere:
    static string EncryptVigenere(string plaintext, string key)
    {
        int textLength = plaintext.Length;
        char[] encryptedText = new char[textLength];

        for (int i = 0; i < textLength; i++)
        {
            // Ignore non-alphabetic characters
            if (!char.IsLetter(plaintext[i]))
            {
                encryptedText[i] = plaintext[i];
                continue;
            }

            // Apply Vigenere cipher formula
            int shift = key[i % key.Length] - 'A';
            encryptedText[i] = (char)((plaintext[i] + shift - 'A') % 26 + 'A');
        }

        return new string(encryptedText);
    }

    static string DecryptVigenere(string ciphertext, string key)
    {
        int textLength = ciphertext.Length;
        char[] decryptedText = new char[textLength];

        for (int i = 0; i < textLength; i++)
        {
            // Ignore non-alphabetic characters
            if (!char.IsLetter(ciphertext[i]))
            {
                decryptedText[i] = ciphertext[i];
                continue;
            }

            // Apply Vigenere cipher formula for decryption
            int shift = key[i % key.Length] - 'A';
            decryptedText[i] = (char)((ciphertext[i] - shift - 'A' + 26) % 26 + 'A');
        }

        return new string(decryptedText);
    }
}
