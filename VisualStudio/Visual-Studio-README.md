NDN-IND for Visual Studio
=========================

## vcpkg

* Install vcpkg from https://docs.microsoft.com/en-us/cpp/build/vcpkg?view=msvc-160#installation .
* To install openssl, in a command prompt change directory to the vcpgk root and enter:

    vcpkg install openssl:x64-Windows

* To install sqlite3, in a command prompt change directory to the vcpkg root and enter:

    vcpkg install sqlite3:x64-Windows

* To add the vcpkg to the path:
    * In the Sytem control panel, click Advanced system settings, then click Environment Variables.
    * In the "System variables" panel, click Path. Click Edit and click New.
    * Enter the vcpkg bin folder, for example
      `C:\Users\user\Documents\GitHub\vcpkg\installed\x64-windows\bin`.
    * Click OK to close the control panels.
    * If Visual Studio is already open, then close and re-open it to get the updated Path.

## ndn-ind.dll

To build ndn-ind.dll:

* Copy `ndn-ind-config.h` from this folder to `include\ndn-ind` in the ndn-ind repository. 
  (This file would normally be created on Unix by running ./configure .)
* In Visual Studio, open `VisualStudio\ndn-ind\ndn-ind.sln` .
* In the toolbar, select the configuration Release x64.
* Right-click on the ndn-ind project and select Properties. Make sure it is set to 
  the configuration Release x64. Under Linker/All Options, open 
  Additional Library Directories. Make sure the directory for `vcpkg\installed\x64-windows\lib`
  is correct. (If you cloned vcpkg in a sibling folder to ndn-ind, then it should be correct.)
  Close the Properties window.
* In the Build menu, click Build Solution.

## Example program

To build an example program and test ndn-ind.dll:

* In Visual Studio, open `VisualStudio\example\example.sln`
* In the toolbar, select the configuration Release x64.
* In the Build menu, click Build Solution.
* Copy `ndn-ind.dll` from the NDN-IND build folder to the application build folder. For
  example, copy `C:\Users\user\Documents\GitHub\ndn-ind\VisualStudio\ndn-ind\x64\Release\ndn-ind.dll`
  to `C:\Users\user\Documents\GitHub\ndn-ind\VisualStudio\example\x64\Release` .
* To run, in the Debug menu, click Start Without Debugging. The default example is
  `test-encode-decode-data.cpp`. You should see example encoding and decoding finishing with
  "Freshly-signed Data signature verification: VERIFIED".
