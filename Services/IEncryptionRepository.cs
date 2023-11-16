using Microsoft.AspNetCore.Components.Forms;

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
        Task SymmetricEncryptFile(IBrowserFile file);
        void SymmetricDecryptFile();
        void AsymmetricEncryptText(string text);
        void AsymmetricDecryptText();
        Task AsymmetricEncryptFile(IBrowserFile file);
        void AsymmetricDecryptFile();
        void HashText();
        void HashFile();
    }
}