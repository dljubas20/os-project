namespace os_project.Services
{
    public interface IEncryptionRepository
    {
        byte[] GetKey();
        byte[] GetIV();
    }
}