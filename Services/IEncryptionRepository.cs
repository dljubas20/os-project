namespace os_project.Services
{
    public interface IEncryptionRepository
    {
        byte[] GetKey();
        byte[] GetIV();
        string GetKeyString();
        string GetIVString();
        void EncryptText(string text);
    }
}