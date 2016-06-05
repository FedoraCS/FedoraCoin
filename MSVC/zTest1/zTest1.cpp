// zTest1.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <tchar.h>
#include "../../src/key.h"
#include "../../src/util.h"
#include "../../src/ui_interface.h"
#include "../../src/base58.h"
#include "../../src/init.h"
#include "../../src/scrypt.h"

#undef printf
using namespace std;


int _tmain(int argc, _TCHAR* argv[])
{
   std::string privKey("T6eLvWpHAeNd6RWN5ZLtGchxai41HGcCP9qvJzJY3P4CmqzWGWW5");
   std::string publickey("LZesT7ETtrTVEf6YAPnaz2M78xvTX3mcQz");

   scrypt_detect_sse2();
   if (0)
   {
      //opens the wallet and gets the private key associated with the bitcoin address
      CKeyID keyID;
      CBitcoinAddress address;
      CKey vchSecret;

      bool fFirstRun = true;
      pwalletMain = new CWallet("wallet.dat");
      DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);

      bool b = address.SetString(publickey);
      b = address.GetKeyID(keyID);
      pwalletMain->GetKey(keyID, vchSecret);
      std::string it = CBitcoinSecret(vchSecret).ToString();

      printf("secret = %s\n", it.c_str());

      Shutdown();
   }

   //takes the above private key and turns it into a coin address
   
   if (0) {
      CBitcoinSecret vchSecret;
      vchSecret.SetString(privKey);
      CKey key = vchSecret.GetKey();
      CPubKey pubkey = key.GetPubKey();
      CBitcoinAddress bitcoinAddress(pubkey.GetID());
      string strAddress = bitcoinAddress.ToString();
      printf("public key = %s\n",strAddress.c_str());
      return 0;

      vector<BYTE> vch;
      vch.resize(1);
      vch.at(0) = 16;

      string it2 = EncodeBase58(&vch[0], &vch[0] + vch.size());

      printf("it2 = %s\n", it2.c_str());
   }

   if (1)
   {
      RandAddSeedPerfmon();
      for (int i = 0; i<200; i++) {
         
         CKey secret;
         secret.MakeNewKey(true);
         CBitcoinSecret vchSecret;
         vchSecret.SetKey(secret);
         CPubKey pubkey = secret.GetPubKey();
         string strAddress = CBitcoinAddress(pubkey.GetID()).ToString();
         //printf("public address = %s\n", strAddress.c_str());
         //printf("secret is %s\n", vchSecret.ToString().c_str());
         //now get the public address from the secret string

         //set CBitcoinSecret object to secret string
         vchSecret.SetString(vchSecret.ToString().c_str());

         //create a new key from the secret object
         CKey key = vchSecret.GetKey();

         //get the public key from the key object
         pubkey = key.GetPubKey();

         //get the bitcoin address from the public key
         CBitcoinAddress btcAddr(pubkey.GetID());
         printf("i=%d  and public address again is = %s\n",i, btcAddr.ToString().c_str());
      }

   }

   return 0;
}

