using Microsoft.AspNetCore.Components.Forms;

namespace os_project.Services
{
    public interface IEncryptionRepository
    {
        void SymmetricEncryptText(string text);
        void SymmetricDecryptText();
        Task SymmetricEncryptFile(IBrowserFile file);
        void SymmetricDecryptFile();
        void AsymmetricEncryptText(string text);
        void AsymmetricDecryptText();
        Task AsymmetricEncryptFile(IBrowserFile file);
        void AsymmetricDecryptFile();
        void SymmetricHashText();
        void AsymmetricHashText();
        void SymmetricHashFile();
        void AsymmetricHashFile();
        void SymmetricSignFile();
        void AsymmetricSignFile();
        bool SymmetricVerifyFileSignature();
        bool AsymmetricVerifyFileSignature();
    }
}