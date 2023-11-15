using System.Security.Cryptography;
using System.Text;

namespace os_project.Services
{
    public class EncryptionRepository : IEncryptionRepository
    {
        private Aes aes;
        private RSA rsa;
        private HashAlgorithm hasher;
        public EncryptionRepository()
        {
            aes = Aes.Create();
            rsa = RSA.Create();
            hasher = SHA256.Create();

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

        public void SymmetricEncryptText(string text)
        {
            Directory.CreateDirectory("SymmetricTextSteps");

            File.WriteAllText("SymmetricTextSteps/01_textToEncrypt.txt", text);
            
            using FileStream fileStream = File.Open("SymmetricTextSteps/02_encryptedText.txt", FileMode.OpenOrCreate);
            using (CryptoStream cryptoStream = new(
                fileStream,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write))
            {
                using (StreamWriter encryptWriter = new(cryptoStream))
                {
                    encryptWriter.Write(text);
                }
            }
        }

        public void SymmetricDecryptText()
        {
            Directory.CreateDirectory("SymmetricTextSteps");
            
            using FileStream fileStream = File.Open("SymmetricTextSteps/02_encryptedText.txt", FileMode.Open);
            using (CryptoStream cryptoStream = new(
                fileStream,
                aes.CreateDecryptor(),
                CryptoStreamMode.Read))
            {
                using (StreamReader decryptReader = new(cryptoStream))
                {
                    string originalText = decryptReader.ReadToEnd();
                    File.WriteAllText("SymmetricTextSteps/03_decryptedText.txt", originalText);
                }
            }
        }

        public void AsymmetricEncryptText(string text)
        {
            Directory.CreateDirectory("AsymmetricTextSteps");

            File.WriteAllText("AsymmetricTextSteps/01_textToEncrypt.txt", text);
            
            byte[] encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1);
            string encryptedText = Convert.ToBase64String(encryptedBytes);

            File.WriteAllText("AsymmetricTextSteps/02_encryptedText.txt", encryptedText);
        }

        public void AsymmetricDecryptText()
        {
            Directory.CreateDirectory("AsymmetricTextSteps");

            string encryptedText = File.ReadAllText("AsymmetricTextSteps/02_encryptedText.txt");
            byte[] decryptedBytes = rsa.Decrypt(Convert.FromBase64String(encryptedText), RSAEncryptionPadding.Pkcs1);

            File.WriteAllText("AsymmetricTextSteps/03_decryptedText.txt", Encoding.UTF8.GetString(decryptedBytes));
        }

        public void HashText()
        {
            Directory.CreateDirectory("SymmetricTextSteps");

            using FileStream fileStream = File.Open("SymmetricTextSteps/01_textToEncrypt.txt", FileMode.Open);

            byte[] hash = hasher.ComputeHash(fileStream);

            File.WriteAllText("SymmetricTextSteps/04_textHash.txt", Convert.ToBase64String(hash));
        }
    }
}