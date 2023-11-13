namespace os_project.Services
{
    public interface IEncryptionRepository
    {
        byte[] GetKey();
        byte[] GetIV();
        string GetKeyString();
        string GetIVString();
        void SymmetricEncryptText(string text);
        void SymmetricDecryptText();
        void HashText();
    }
}