/* eslint-disable no-unused-vars */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import axios from 'axios';

import {
  Heading, HStack, Text, useRadioGroup, Stack, Flex, useDisclosure, Button, Input, Alert, AlertDescription, useToast,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  AlertTitle
} from '@chakra-ui/react';
import { RadioCard } from '../components/RadioCard';
import { useSubstrate } from '../substrate-lib';
import { validNumArr, PATH } from './Owner';

export const Purchaser = () => {
  const [accountAddress, setAccountAddress] = useState(null);
  const [isAgreed, setIsAgreed] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [transfering, setTransfering] = useState(false);
  const [retrievingDk, setRetrievingDk] = useState(false);
  const [retrievingCipher, setRetrievingCipher] = useState(false);
  const [type, setType] = useState('InnerProduct');
  const [dataId, setDataId] = useState('');
  const [decryptDataId, setDecryptDataId] = useState('');
  const [userId, setUserId] = useState('');
  const [ciphertext, setCiphertext] = useState({});
  const [rawData, setRawData] = useState('');
  const [rawDataInput, setRawDataInput] = useState('');
  const [DK, setDK] = useState({});
  const [rows, setRows] = useState('');
  const [cols, setCols] = useState('');
  const [rawDataErr, setRawDataErr] = useState('');
  const [signature, setSignatrue] = useState('');
  const [decryptData, setDecryptData] = useState('');
  const [GH, setGH] = useState('');

  const { isOpen, onOpen, onClose } = useDisclosure();

  const loadingMsg = useRef(null);

  const toast = useToast();

  const { api, apiState, keyring, keyringState } = useSubstrate();
  const accountPair =
    keyringState === 'READY' &&
    keyring.getPair(process.env.REACT_APP_PURCHASER_ADDRESS);

  useEffect(() => {
    if (!rawData) {
      return;
    }
    const rawDatas = rawData.split(',');
    if (!validNumArr(rawDatas)) {
      setRawDataErr('Please enter numbers seperate with "," e.g. 1,2');
      toast({
        status: 'error',
        position: 'top-right',
        description: 'Please enter numbers seperate with "," e.g. 1,2'
      });
    } else {
      setRawDataInput(rawDatas.map(item => Number(item)));
      setRawDataErr('');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rawData]);

  useEffect(() => {
    const agreed = window.localStorage.getItem('agreement');
    if (agreed) {
      setIsAgreed(true);
    }
  }, []);

  const options = ['InnerProduct', 'Quadratic'];
  const { getRootProps, getRadioProps } = useRadioGroup({
    name: 'format',
    defaultValue: 'InnerProduct',
    onChange: (data) => {
      console.log(data);
      setType(data);
    }
  });
  const group = getRootProps();

  const [getingGH, setGetingGH] = useState(false);
  const handleGetGH = async () => {
    setGetingGH(true);

    try {
      let _gh = await axios.get('/purchaser/g_h');
      _gh = _gh.data.match(/\d+/g);
      const g = {
        x: _gh[0],
        y: _gh[1]
      };
      const h = {
        x: _gh[2],
        y: _gh[3]
      };
      const params = {
        buyernumber: Number(userId),
        g: JSON.stringify(g),
        h: JSON.stringify(h)
      };
      setGH(JSON.stringify(_gh));
      console.log(_gh);
      await axios.post('/authority/add/gh', params);
      toast({
        status: 'success',
        description: 'Get GH successful',
        position: 'top-right'
      });
    } catch (err) {
      toast({
        status: 'error',
        description: err.message,
        position: 'top-right'
      });
    }

    setGetingGH(false);
  };

  const handleRetrieveDK = async () => {
    console.log(type);
    // TODO check diffrent format with ip and qua
    const data = {
      buyernumber: Number(userId),
      ciphernumber: Number(decryptDataId)
    };

    try {
      setRetrievingDk(true);

      const cipher = await axios.post(`/authority/${PATH[type]}/dk`, data);
      console.log(cipher.data);
      setDK(cipher.data);
      toast({
        description: 'Retrieved successful',
        position: 'top-right',
        status: 'success'
      });
    } catch (error) {
      console.log(error);
      toast({
        description: error.message,
        position: 'top-right',
        status: 'error'
      });
    }
    setRetrievingDk(false);
  };
  const handleTransfer = useCallback(() => {
    console.log('handleTransfer');
    if (!GH) {
      toast({
        status: 'error',
        description: 'Please get gh',
        position: 'top-right'
      });
      return;
    }
    const params = {
      buyernumber: Number(userId),
      ciphernum: Number(dataId)
    };

    if (type === 'InnerProduct') {
      params.y = rawDataInput;
    } else {
      params.matrix = {
        data: rawDataInput,
        n_rows: Number(rows),
        n_cols: Number(cols)
      };
    }

    let unsub = null;
    if (apiState === 'READY') {
      const asyncFn = async () => {
        try {
          if (api) {
            setTransfering(true);
            const receiver = process.env.REACT_APP_AUTHORITY_ADDRESS;
            const amount = 1000000000000; // 1 DOT

            console.log(accountPair);

            await axios.post(`/authority/${PATH[type]}/fe`, params);
            unsub = await api.tx.balances
              .transfer(receiver, amount)
              .signAndSend(accountPair, ({ events = [], status }) => {
                console.log(status);

                if (status.isReady) {
                  toast({
                    description: 'Waiting...',
                    status: 'info',
                    duration: null,
                    id: 'waiting',
                    position: 'top-right'
                  });
                } else if (status.isInBlock || status.isFinalized) {
                  events.forEach(async ({ event }) => {
                    console.log(event);

                    if (event.method === 'ExtrinsicSuccess') {
                      toast({
                        status: 'success',
                        description: 'succeed',
                        position: 'top-right'
                      });
                    } else if (event.method === 'ExtrinsicFailed') {
                      toast({
                        description: 'Transaction failed.',
                        duration: 3000,
                        position: 'top-right',
                        status: 'error'
                      });
                    }
                  });
                  toast.close('waiting');

                  setTransfering(false);
                  unsub();
                }
              });
          }
        } catch (err) {
          toast({
            description: err.message || err.tostring() || 'Error occured while transaction.',
            duration: 3000,
            position: 'top-right',
            status: 'error'
          });

          setTransfering(false);
          unsub && unsub();
        }
      };

      asyncFn();
    }

    return () => {
      unsub && unsub();
    };
  }, [accountPair, api, apiState, cols, dataId, GH, rawDataInput, rows, toast, type, userId]);
  const handleRetrieveCipher = async () => {
    // TODO check diffrent format with ip and qua
    const data = {
      buyernumber: Number(userId),
      ciphernumber: Number(decryptDataId)
    };
    try {
      setRetrievingCipher(true);
      const cipher = await axios.post(`/authority/${PATH[type]}/cipher`, data);
      setCiphertext(cipher.data);
      console.log(cipher);
    } catch (error) {
      console.log(error.message);
      toast({
        description: error.message,
        status: 'error',
        position: 'top-right'
      });
    }
    setRetrievingCipher(false);
  };
  const handleDecrypt = async () => {
    console.log('handleDecrypt');
    try {
      setDecrypting(true);
      const data = {
        ciphers: ciphertext
      };
      if (type === 'InnerProduct') {
        data.dks = DK;
      } else {
        data.dks = {
          key: [DK[0].key],
          data: [DK[1].data],
          modulus: DK[1].modulus,
          n_rows: DK[2].n_rows,
          n_cols: DK[2].n_cols
        };
      }
      const result = await axios.post(`/purchaser/${PATH[type]}/decrypt`, data);
      console.log(result);
      setDecryptData(result.data);
      onOpen();
      toast({
        description: 'Decrypt successful',
        position: 'top-right',
        status: 'success'
      });
    } catch (error) {
      toast({
        description: error.message,
        position: 'top-right',
        status: 'error'
      });
    }
    setDecrypting(false);
  };

  const handleSign = async () => {
    console.log('handleSign');
    const message = 'I have read and agreed with this Terms.';
    window.localStorage.setItem('agreement', message);

    // const injector = await web3FromAddress(accountPair.address);
    // api.setSigner(injector.signer);
    // const signRaw = injector?.signer?.signRaw;
    // try {
    //   if (signRaw) {
    //     // after making sure that signRaw is defined
    //     // we can use it to sign our message
    //     const { signature } = await signRaw({
    //       address: accountPair.address,
    //       data: message,
    //       type: 'bytes'
    //     });
    //     console.log(`${(signature)}`);
    //     setSignatrue(signature);

    //     const publickey = keyring.decodeAddress(accountPair.address);
    //     const verification = signatureVerify(message, signature, publickey);
    //     console.log(verification.crypto, verification.isValid);
    //   }
    // } catch (err) {
    //   toast({
    //     status: 'error',
    //     position: 'top-right',
    //     title: err.message
    //   });
    // }

    console.log(accountPair);
    setIsAgreed(true);
  };

  return (
    <Flex w='100%' direction='column' p='1rem' alignItems='center' background='gray.50' borderRadius='1rem'>
      <Heading>Data Purchaser</Heading>
      {isAgreed ? (
        <>

          <br/>
          <HStack {...group} mb='1rem'>
            {options.map((value) => {
              const radio = getRadioProps({ value });
              return (
                <RadioCard key={value} {...radio}>
                  {value}
                </RadioCard>
              );
            })}
          </HStack>
          <Flex w='100%' direction='Row' mt='2rem'>
            <Stack w='50%' p='2rem' spacing={3}>
              <Input
                isInvalid={!!rawDataErr}
                errorBorderColor='crimson'
                value={rawData}
                onChange={(e) => setRawData(e.target.value)}
                background='white'
                placeholder='Please enter your Raw data' />

              {
                type === 'Quadratic' && (
                  <>
                    <Input value={rows} onChange={(e) => setRows(e.target.value)} type={'number'} background='white' placeholder='Please enter rows'/>
                    <Input value={cols} onChange={(e) => setCols(e.target.value)} type={'number'} background='white' placeholder='Please enter cols'/>
                  </>
                )
              }
              {/* <Input value={rawData} onChange={(e) => setRawData(e.target.value)} background='white' placeholder='Please enter your Raw data, seperate with "," e.g. 1,2'/> */}
              <Input
                value={dataId}
                onChange={(e) => setDataId(e.target.value)}
                type={'number'}
                background='white'
                placeholder='Please enter Data id'/>
              <Input value={userId} onChange={(e) => setUserId(e.target.value)} type={'number'} background='white' placeholder='Please enter your user id'/>
              <p>
                <span>Cost: </span><b>1 DOT</b>
              </p>
              <Button colorScheme='pink' mr={3} isLoading={getingGH} onClick={handleGetGH}>
                Get PK_P
              </Button>
              {
                GH &&
                <Alert status='success'>
                  <AlertTitle>GH:</AlertTitle>
                  <AlertDescription>
                    {JSON.stringify(GH)}
                  </AlertDescription>
                </Alert>
              }
              <Button disabled={!(dataId && rawData && userId && GH)} isLoading={transfering} colorScheme='pink' onClick={handleTransfer}>Inputs for derive_fe_key</Button>
            </Stack>
            <Stack w='50%' p='2rem'>
              <Stack spacing={3}>
                <Input value={decryptDataId} onChange={(e) => setDecryptDataId(e.target.value)} background='white' placeholder='Please enter Data id'/>
                {
                  JSON.stringify(ciphertext) !== '{}' ? (
                    <Alert status='info'>
                      <AlertDescription>
                        <b>
                          Cipher:
                        </b>
                        {JSON.stringify(ciphertext)}
                      </AlertDescription>
                    </Alert>
                  ) : 'Press the below button to retrieve the Ciphertext'
                }
                <Input value={userId} onChange={(e) => setUserId(e.target.value)} background='white' placeholder='Please enter your user id'/>
                <Button colorScheme='pink' disabled={!(decryptDataId && userId)} isLoading={retrievingCipher} onClick={handleRetrieveCipher}>Retrieve Ciphertext</Button>

                {
                  JSON.stringify(DK) !== '{}' ? (
                    <Alert status='info'>
                      <AlertDescription>
                        <b>
                          DK:
                        </b>
                        {JSON.stringify(DK)}
                      </AlertDescription>
                    </Alert>
                  ) : 'Press the below button to retrieve the DK'
                }
                <Button disabled={!(userId && decryptDataId)} colorScheme='pink' isLoading={retrievingDk} onClick={handleRetrieveDK}>Retrieve DK</Button>
                <Button disabled={!ciphertext || !DK } isLoading={decrypting} colorScheme='pink' onClick={handleDecrypt}>Decrypt</Button>

              </Stack>
            </Stack>
          </Flex></>
      ) : (
        <Stack spacing={3}>

          {/* <AccountSelector setAccountAddress={setAccountAddress} /> */}
          <Text>
            Agreement
          </Text>
          <Button onClick={handleSign}>Sign and send</Button>
        </Stack>
      )}

      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Decrypt content</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {decryptData}
          </ModalBody>

          <ModalFooter>
            <Button colorScheme='blue' mr={3} onClick={onClose}>
              Close
            </Button>
            <Button variant='ghost' onClick={onClose}>Ok</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Flex>
  );
};
