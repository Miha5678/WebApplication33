using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
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
        if (Algorithm == "AES")
        {
            EncryptDecryptAES();
        }
        else if (Algorithm == "RSA")
        {
            EncryptDecryptRSA();
        }
    }

    private void EncryptDecryptAES()
    {
        using var aes = Aes.Create();

        if (string.IsNullOrWhiteSpace(EncryptionKey))
        {
            EncryptionKey = "defaultencryptionkey"; 
        }

        byte[] keyBytes = Encoding.UTF8.GetBytes(EncryptionKey);

    
        if (keyBytes.Length < 32)
        {
            Array.Resize(ref keyBytes, 32);
        }
        else if (keyBytes.Length > 32)
        {
            keyBytes = keyBytes.Take(32).ToArray();
        }

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
}
