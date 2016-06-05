
These batch and project files build all the dependencies you need for the *coin daemon and Qt application, both 32 and 64 bit versions.  But you need to fix them up before you can use them.  The first thing you should do is move this folder to the root of your BitcoinDeps directory.  You also need to make sure that ActivePerl is in your path and MSVC12 is installed in it's normal place.  If not, edit the batch file as needed.

Next, before executing individual batch files to build a dependency, you must make sure that your directories match.   Open up each batch file in an editor and take a good look--do you have all the directories that it is expecting?  I have them hard-coded right now for my setup--for example, the first thing the openssl batch file does is this:

  cd C:\MyProjects\BitcoinDeps\openssl-1.0.1e
  
Do you have that version of openssl in that directory?  If not, edit the batch file to match what you have.

For Qt, I have two batch files, one for 32 and for 64 bit.  I would keep a pristine, untouched copy of the Qt distribution handy in case you mess up so that you can just start with a fresh copy easily. !!!!Also!!!! Pay attention to that configure line in both Qt batch files since they reference the openssl distro directory--Make sure it matches and that you have already built openssl first!!!

A side note--all the batch files and project files build static libs with static runtime c lib linkage.  I didn't like seeing the 4099 linker warnings due to the linker not being able to find the PDB files if I moved or renamed the bitcoindeps folder, so I use the /Z7 flag to embed the debug information into the object file.  This was mostly an experiment.  I'm thinking of going back to using /Zi.  We'll see, I'm still thinking about it because using the /Zi flag gives you the ability to do incremental linking, which is faster if you do a lot of compiling.

