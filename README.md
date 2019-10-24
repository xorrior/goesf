# goesf
Golang command line tool for the macOS Endpoint Security Framework

- Requires macOS 10.15+ to build
- Build command: go build 
- Sign the resulting binary with codesign and the entitlements.xml file:
  - Find eligible identities for codesigning: `security find-identity -v -p codesigning`
  - Sign the binary: `codesign -s '[Code Signing Identity]' --entitlements entitlements.xml [golang binary]`
