using System.Security.Cryptography;
using System.Text;

namespace os_project.Services
{
    public class EncryptionRepository : IEncryptionRepository
    {
        private Aes aes;
        public EncryptionRepository()
        {
            aes = Aes.Create();

            Directory.CreateDirectory("Keys");
            using (StreamWriter streamWriter = new StreamWriter(Path.Combine("Keys", "tajni_kljuc.txt")))
            {
                streamWriter.Write(Encoding.UTF8.GetString(aes.Key));
            }
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
    }
}