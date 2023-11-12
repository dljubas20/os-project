using System.Security.Cryptography;

namespace os_project.Services
{
    public class EncryptionRepository : IEncryptionRepository
    {
        private Aes aes;
        private RSA rsa;
        public EncryptionRepository()
        {
            aes = Aes.Create();
            rsa = RSA.Create();

            Directory.CreateDirectory("Keys");
            File.WriteAllText("Keys/tajni_kljuc.txt", Convert.ToBase64String(aes.Key));
            File.WriteAllText("Keys/javni_kljuc.txt", Convert.ToBase64String(rsa.ExportRSAPublicKey()));
            File.WriteAllText("Keys/privatni_kljuc.txt", Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
        }

        public byte[] GetKey()
        {
            return aes.Key;
        }

        public byte[] GetIV()
        {
            return aes.IV;
        }

        public string GetKeyString()
        {
            return Convert.ToBase64String(aes.Key);
        }

        public string GetIVString()
        {
            return Convert.ToBase64String(aes.IV);
        }

        public void EncryptText(string text)
        {
            Directory.CreateDirectory("TextSteps");

            File.WriteAllText("TextSteps/01_textToEncrypt.txt", text);
            
            using (CryptoStream cryptoStream = new(
                File.Open("TextSteps/02_encryptedText.txt", FileMode.OpenOrCreate),
                aes.CreateEncryptor(),
                CryptoStreamMode.Write))
            {
                using (StreamWriter encryptWriter = new(cryptoStream))
                {
                    encryptWriter.Write(text);
                }
            }
        }
    }
}