using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Sodium;
using System.Security.Cryptography;
using System.Text;

public class IndexModel : PageModel
{
    [BindProperty] public string InputText { get; set; }
    [BindProperty] public string EncryptionKey { get; set; }
    [BindProperty] public string Algorithm { get; set; }
    public string EncryptedText { get; set; }
    public string DecryptedText { get; set; }

    public void OnPostEncrypt()
    {
        switch (Algorithm)
        {
            case "AES":
                EncryptDecryptAES();
                break;
            case "RSA":
                EncryptDecryptRSA();
                break;
            case "BouncyCastle":
                EncryptDecryptBouncyCastle();
                break;
            case "Libsodium":
                EncryptDecryptLibsodium();
                break;
        }
    }

    private void EncryptDecryptAES()
    {
        using var aes = Aes.Create();

        if (string.IsNullOrWhiteSpace(EncryptionKey))
            EncryptionKey = "defaultencryptionkey";

        byte[] keyBytes = Encoding.UTF8.GetBytes(EncryptionKey);
        if (keyBytes.Length < 32)
            Array.Resize(ref keyBytes, 32);
        else if (keyBytes.Length > 32)
            keyBytes = keyBytes.Take(32).ToArray();

        aes.Key = keyBytes;
        aes.IV = new byte[16];

        var encryptor = aes.CreateEncryptor();
        var inputBytes = Encoding.UTF8.GetBytes(InputText);
        var encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
        EncryptedText = Convert.ToBase64String(encryptedBytes);

        var decryptor = aes.CreateDecryptor();
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
        DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
    }

    private void EncryptDecryptRSA()
    {
        using var rsa = RSA.Create();
        rsa.KeySize = 2048;

        var inputBytes = Encoding.UTF8.GetBytes(InputText);
        var encryptedBytes = rsa.Encrypt(inputBytes, RSAEncryptionPadding.Pkcs1);
        EncryptedText = Convert.ToBase64String(encryptedBytes);

        var decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
        DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
    }

    private void EncryptDecryptBouncyCastle()
    {
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = keyGen.GenerateKeyPair();

        var encryptEngine = new RsaEngine();
        encryptEngine.Init(true, keyPair.Public);
        var inputBytes = Encoding.UTF8.GetBytes(InputText);
        var encryptedBytes = encryptEngine.ProcessBlock(inputBytes, 0, inputBytes.Length);
        EncryptedText = Convert.ToBase64String(encryptedBytes);

        var decryptEngine = new RsaEngine();
        decryptEngine.Init(false, keyPair.Private);
        var decryptedBytes = decryptEngine.ProcessBlock(encryptedBytes, 0, encryptedBytes.Length);
        DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
    }

    private void EncryptDecryptLibsodium()
    {
        if (string.IsNullOrWhiteSpace(EncryptionKey))
            EncryptionKey = "defaultencryptionkey";

        var keyBytes = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32, '0')).Take(32).ToArray();
        var nonce = SodiumCore.GetRandomBytes(24);
        var inputBytes = Encoding.UTF8.GetBytes(InputText);

        var encryptedBytes = SecretBox.Create(inputBytes, nonce, keyBytes);
        EncryptedText = $"{Convert.ToBase64String(nonce)}:{Convert.ToBase64String(encryptedBytes)}";

        var parts = EncryptedText.Split(':');
        var decryptedBytes = SecretBox.Open(Convert.FromBase64String(parts[1]), Convert.FromBase64String(parts[0]), keyBytes);
        DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
    }
}
