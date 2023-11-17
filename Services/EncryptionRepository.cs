using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Components.Forms;

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

        public async Task SymmetricEncryptFile(IBrowserFile file)
        {
            Directory.CreateDirectory("SymmetricFileSteps");

            using FileStream fileStreamOriginal = File.Open("SymmetricFileSteps/" + file.Name, FileMode.OpenOrCreate);
            await file.OpenReadStream().CopyToAsync(fileStreamOriginal);

            using (FileStream fileStreamSave = File.Open("SymmetricFileSteps/01_fileToEncrypt", FileMode.OpenOrCreate))
            {
                await file.OpenReadStream().CopyToAsync(fileStreamSave);
            }

            using FileStream fileStreamEncrypt = File.Open("SymmetricFileSteps/02_encryptedFile", FileMode.OpenOrCreate);

            using (CryptoStream cryptoStream = new(
                fileStreamEncrypt,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write))
            {
                using FileStream fileStreamSave = File.Open("SymmetricFileSteps/01_fileToEncrypt", FileMode.Open);
                fileStreamSave.CopyTo(cryptoStream);
            }
        }

        public void SymmetricDecryptFile()
        {
            Directory.CreateDirectory("SymmetricFileSteps");
            
            using FileStream fileStreamEncrypted = File.Open("SymmetricFileSteps/02_encryptedFile", FileMode.Open);
            using FileStream fileStreamDecrypt = File.Open("SymmetricFileSteps/03_decryptedFile", FileMode.OpenOrCreate);
            
            using (CryptoStream cryptoStream = new(
                fileStreamDecrypt,
                aes.CreateDecryptor(),
                CryptoStreamMode.Write))
            {
                fileStreamEncrypted.CopyTo(cryptoStream);
            }
        }

        public async Task AsymmetricEncryptFile(IBrowserFile file)
        {
            Directory.CreateDirectory("AsymmetricFileSteps");

            using FileStream fileStreamOriginal = File.Open("AsymmetricFileSteps/" + file.Name, FileMode.OpenOrCreate);
            await file.OpenReadStream().CopyToAsync(fileStreamOriginal);

            using (FileStream fileStreamSave = File.Open("AsymmetricFileSteps/01_fileToEncrypt", FileMode.OpenOrCreate))
            {
                await file.OpenReadStream().CopyToAsync(fileStreamSave);
            }

            using (MemoryStream ms = new())
            {
                using FileStream fileStreamSave = File.Open("AsymmetricFileSteps/01_fileToEncrypt", FileMode.Open);
                
                fileStreamSave.CopyTo(ms);
                
                byte[] encryptedBytes = rsa.Encrypt(ms.ToArray(), RSAEncryptionPadding.Pkcs1);
                File.WriteAllBytes("AsymmetricFileSteps/02_encryptedFile", encryptedBytes);
            }
        }

        public void AsymmetricDecryptFile()
        {
            Directory.CreateDirectory("AsymmetricFileSteps");
            
            byte[] encryptedBytes = File.ReadAllBytes("AsymmetricFileSteps/02_encryptedFile");
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

            File.WriteAllBytes("AsymmetricFileSteps/03_decryptedFile", decryptedBytes);
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

        public void SymmetricHashText()
        {
            Directory.CreateDirectory("SymmetricTextSteps");

            using FileStream fileStream = File.Open("SymmetricTextSteps/01_textToEncrypt.txt", FileMode.Open);

            byte[] hash = hasher.ComputeHash(fileStream);

            File.WriteAllText("SymmetricTextSteps/04_textHash.txt", Convert.ToBase64String(hash));
        }

        public void AsymmetricHashText()
        {
            Directory.CreateDirectory("AsymmetricTextSteps");

            using FileStream fileStream = File.Open("AsymmetricTextSteps/01_textToEncrypt.txt", FileMode.Open);

            byte[] hash = hasher.ComputeHash(fileStream);

            File.WriteAllText("AsymmetricTextSteps/04_textHash.txt", Convert.ToBase64String(hash));
        }

        public void SymmetricHashFile()
        {
            Directory.CreateDirectory("SymmetricFileSteps");

            using FileStream fileStream = File.Open("SymmetricFileSteps/01_fileToEncrypt", FileMode.Open);

            byte[] hash = hasher.ComputeHash(fileStream);

            File.WriteAllText("SymmetricFileSteps/04_fileHash", Convert.ToBase64String(hash));
        }

        public void AsymmetricHashFile()
        {
            Directory.CreateDirectory("AsymmetricFileSteps");

            using FileStream fileStream = File.Open("AsymmetricFileSteps/01_fileToEncrypt", FileMode.Open);

            byte[] hash = hasher.ComputeHash(fileStream);

            File.WriteAllText("AsymmetricFileSteps/04_fileHash", Convert.ToBase64String(hash));
        }

        public void SymmetricSignFile()
        {
            RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
            rsaFormatter.SetHashAlgorithm(nameof(SHA256));

            byte[] hash = Convert.FromBase64String(File.ReadAllText("SymmetricFileSteps/04_fileHash"));

            byte[] signedHash = rsaFormatter.CreateSignature(hash);

            File.WriteAllText("SymmetricFileSteps/05_fileSignature", Convert.ToBase64String(signedHash));
        }

        public void AsymmetricSignFile()
        {
            RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
            rsaFormatter.SetHashAlgorithm(nameof(SHA256));

            byte[] hash = Convert.FromBase64String(File.ReadAllText("AsymmetricFileSteps/04_fileHash"));

            byte[] signedHash = rsaFormatter.CreateSignature(hash);

            File.WriteAllText("AsymmetricFileSteps/05_fileSignature", Convert.ToBase64String(signedHash));
        }

        public bool SymmetricVerifyFileSignature()
        {
            RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
            rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

            try
            {
                byte[] hash = Convert.FromBase64String(File.ReadAllText("SymmetricFileSteps/04_fileHash"));

                byte[] signedHash = Convert.FromBase64String(File.ReadAllText("SymmetricFileSteps/05_fileSignature"));

                if(rsaDeformatter.VerifySignature(hash, signedHash))
                {
                    return true;
                } else {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool AsymmetricVerifyFileSignature()
        {
            RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
            rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

            try
            {
                byte[] hash = Convert.FromBase64String(File.ReadAllText("AsymmetricFileSteps/04_fileHash"));

                byte[] signedHash = Convert.FromBase64String(File.ReadAllText("AsymmetricFileSteps/05_fileSignature"));

                if(rsaDeformatter.VerifySignature(hash, signedHash))
                {
                    return true;
                } else {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}