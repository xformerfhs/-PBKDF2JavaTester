# PBKDF2JavaTester

This is an example program to test various PBKDF2 functions in Java. It was created to show 1. how to use the PBKDF2 functions in Java to encode passwords and 2. to play with various parameters to see the result.

The program is called with the following parameters:

```
java -jar PBKDF2.jar <hashType> <salt> <iterationCount> <password> [<doItRight>]
```
where the parameters have the following meanings:

| Parameter | Meaning |
| --------- | ------- |
| `hashType` | 1=SHA-1, 2=SHA-256, 3=SHA-384, 5=SHA-512 (Note: hashType 1 works on all Java versions. All other hashTypes are supported beginning with Java 8) |
| `salt` | The salt of the PBKDF2 function. The interpretation of this parameter depends on the presence of the `doItRight` parameter |
| `iterationCount` | The iteration count for the PBKDF2 function |
| `password` | The password that is used in the PBKDF2 function |
| `doItRight` | If there is any parameter following the password the salt is treated as a byte array. If there is nothing following the password the salt is treated as an integer |

The program has 2 modi. In the first modus (the "wrong" modus) it interprets the "salt" as an integer. This is a common misconception and found quite often on the internet.

In the second modus it interprets the "salt" as a byte array which is the correct way to handle it.

Here are some examples:

```
java -jar PBKDF2.jar 1 81726354 123456 Veyron
```

This yields

```
HashType: SHA1, Salt: 81726354, IterationCount: 123456, Password: 'Veyron', PBKDF2: 57 60 62 1F 2C 20 23 57 87 08 9D 40 4B 9D 26 EA B0 6B 9B C6
Duration: 421 ms
```

Note, that this is a wrong calculation as the salt is interpreted as an integer. Here is the correct version

```
java -jar PBKDF2.jar 1 04df0b92 123456 Veyron x
```

which yields

```
HashType: SHA1, Salt: 04 DF 0B 92, IterationCount: 123456, Password: 'Veyron', PBKDF2: 57 60 62 1F 2C 20 23 57 87 08 9D 40 4B 9D 26 EA B0 6B 9B C6
Duration: 406 ms
```
