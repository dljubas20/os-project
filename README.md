# os-project

Projekt je izrađen koristeći Blazor Server (.NET Core 6.0) - C#. Projekt je u potpunosti izrađen i testiran na Linux Mint 21.2 (Victoria).

---

## Upute za pokretanje

1. Pozicionirati se u direktorij `/publish`.
2. U terminalu pokrenuti `./os-project`.
3. Poslužitelj je pokrenut na https://localhost:5001.

#### Alternativni način pokretanja - potreban .NET Core 6.0

Pozicionirati se u korijenski direktorij projekta i pokrenuti naredbu:

```sh
dotnet run
```

## Upute za kriptiranje

1. S lijeve strane se nalazi izbornik s opcijama:
    * Symmetric Encrypt-Text
    * Symmetric Encrypt-File
    * Asymmetric Encrypt-Text
    * Asymmetric Encrypt-File

2. Na simetričnom kriptiranju datoteke se ključ automatski čita iz datoteke tajni_kljuc.txt pa je potrebno samo odabrati datoteku koja će se kriptirati, a zatim poklikati gumbove redom kako se otključavaju:
    * UPLOAD AND ENCRYPT
    * DECRYPT
    * GENERATE HASH
    * GENERATE SIGNATURE
    * VERIFY SIGNATURE

3. Rezultati svih ovih koraka se mogu vidjeti u pripadajućem direktoriju, koji se generirao unutar `/publish`. Naziv direktorija je `SymmetricFileSteps`.

## O strukturi izvornog koda

Struktura samih stranica se nalazi u `/Pages` direktoriju, gdje su glavne 4 stranice:
* `AsymmetricEncryptionFile.razor`
* `AsymmetricEncryptionText.razor`
* `SymmetricEncryptionFile.razor`
* `SymmetricEncryptionText.razor`

Logika iza enkripcije, dekripcije, sažetka i potpisa je u direktoriju `/Services`:
* `EncryptionRepository.cs` - klasa s implementacijom svih metoda potrebnih za izradu projekta.
* `IEncryptionRepository.cs` - sučelje s definiranim metodama. Sučelje je bilo potrebno kako bi se obavio `Dependency Injection` implementacije klase u same stranice bez potrebe za pisanjem cijele logike u datotekama koje su namijenjene samo za izgled stranice u `/Pages` direktoriju.