# Ruby-ui

## Step1
- Open the Authority page press “Init sip and sgp”
![Ruby ui](operations/1.png?raw=true)

## Step2
- Open the Owner page, choose Innerproduct or quadratic, press “Retrieve Public key” Button, then input data, data id ,
owner user id then encrypt and upload.
![Ruby ui](operations/2.png?raw=true)
## Step3
- Open the Purchaser page. Choose either Innerproduct or quadratic as the owner does. Enter raw vector, data id(owner’s data id) ,
and purchaser user id then press ”Inputs for derive_fe_key”. The underlying substrate module will automatically
charge a certain amount of Dot from the purchaser’s account.
![Ruby ui](operations/3.png?raw=true)

## Step4
1. Open the Authority page. Select either Innerproduct or quadratic as the owner does. Enter data id(owner’s data id) ,
purchaser user id then press “Derive functional key & Generate ZKP” button to derive dk.
2. When the functional key is derived, press “Set verification key for ZKP” and then “Verify the ZKP & Transfer token” to verify
the validity of the generated dk. The token will be transferred to the owner’s account when the verification passes.
![Ruby ui](operations/4.png?raw=true)

## Step5
- Open the Purchaser page. Select either Innerproduct or quadratic as the owner does. Enter the owner’s data id and
Purchaser’s user id then press the “Retrieve ciphertext” and “Retrieve DK” button to retrieve the ciphertext and DK.
Then press the “Decrypt” button to get the decryption result.
![Ruby ui](operations/5.png?raw=true)
![Ruby ui](operations/6.png?raw=true)