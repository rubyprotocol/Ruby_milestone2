import React, { useEffect, useState } from 'react';

import { Heading, HStack, useRadioGroup, Stack, useToast, Box, Flex, Button, Input, Alert, AlertTitle, AlertDescription } from '@chakra-ui/react';
import { RadioCard } from '../components/RadioCard';
import axios from 'axios';

import { hexToU8a, isHex } from '@polkadot/util';
import { decodeAddress, encodeAddress } from '@polkadot/keyring';
export const PATH = {
  InnerProduct: 'ip',
  Quadratic: 'qua'
};
const isValidAddressPolkadotAddress = (address) => {
  address = address.trim();
  try {
    encodeAddress(isHex(address) ? hexToU8a(address) : decodeAddress(address));

    return true;
  } catch (error) {
    return false;
  }
};

export const validNumArr = (nums) => {
  if (!nums.length) {
    return;
  }
  // eslint-disable-next-line no-useless-escape
  const numReg = /^(\-|\+|\.)?\d+(\.\d+)?$/;
  let result = false;

  nums.forEach(item => {
    if (numReg.test(item)) {
      result = true;
    }
  });
  return result;
};

export const Owner = () => {
  const toast = useToast();
  const [type, setType] = useState('InnerProduct');
  const [publicKey, setPublicKey] = useState({
    InnerProduct: '',
    Quadratic: ''
  });
  const [retrieving, setRetrieving] = useState(false);
  const [rawData, setRawData] = useState('');
  const [rawDataInput, setRawDataInput] = useState('');

  const [rawDataYInput, setRawDataYInput] = useState('');
  const [rawDataY, setRawDataY] = useState('');
  const [address, setAddress] = useState('');
  const [dataId, setDataId] = useState('');
  const [rawDataErr, setRawDataErr] = useState('');
  const [rawDataYErr, setRawDataYErr] = useState('');
  const [addressErr, setAddressErr] = useState('');
  const [dataIdErr, setDataIdErr] = useState('');

  const [disabledEncrypt, setDisabledEncrypt] = useState(false);

  const [uploading, setUploading] = useState(false);
  const [ciphertext, setCiphertext] = useState('');

  useEffect(() => {
    const isQua = type === 'Quadratic';
    if (isQua) {
      if (!(rawData && rawDataY && dataId && address) || rawDataErr || dataIdErr || addressErr || rawDataYErr) {
        setDisabledEncrypt(true);
      } else {
        setDisabledEncrypt(false);
      }
    } else {
      if (!(rawData && dataId && address) || rawDataErr || dataIdErr || addressErr) {
        setDisabledEncrypt(true);
      } else {
        setDisabledEncrypt(false);
      }
    }
  }, [address, addressErr, dataId, dataIdErr, rawData, rawDataErr, rawDataY, rawDataYErr, type]);

  useEffect(() => {
    if (!rawData) {
      return;
    }
    const rawDatas = rawData.split(',');
    console.log(rawDatas);
    if (!validNumArr(rawDatas)) {
      setRawDataErr('Please enter numbers seperate with "," e.g. 1,2');
      toast({
        status: 'error',
        position: 'top-right',
        description: 'Please enter numbers seperate with "," e.g. 1,2'
      });
    } else {
      setRawDataErr('');
      setRawDataInput(rawDatas.map(item => Number(item)));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rawData]);

  useEffect(() => {
    if (!rawDataY) {
      return;
    }
    const rawDatas = rawDataY.split(',');
    console.log(rawDatas);
    if (!validNumArr(rawDatas)) {
      setRawDataYErr('Please enter numbers seperate with "," e.g. 1,2');
      toast({
        status: 'error',
        position: 'top-right',
        description: 'Please enter numbers seperate with "," e.g. 1,2'
      });
    } else {
      setRawDataYInput(rawDatas.map(item => Number(item)));
      setRawDataYErr('');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rawDataY]);
  useEffect(() => {
    if (!dataId) {
      return;
    }
    if (!/^[1-9]\d*$/.test(dataId)) {
      setDataIdErr('Please enter valid data id');
      toast({
        status: 'error',
        position: 'top-right',
        description: 'Please enter valid data id'
      });
    } else {
      setDataIdErr('');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataId]);
  useEffect(() => {
    if (!address) {
      return;
    }
    if (!isValidAddressPolkadotAddress(address)) {
      setAddressErr('Please enter valid address');
      toast({
        status: 'error',
        position: 'top-right',
        description: 'Please enter valid address'
      });
    } else {
      setAddressErr('');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address]);

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

  const handleRetrieve = () => {
    setRetrieving(true);
    const initIp = () => axios.get('/authority/ip/mpk');
    const initQua = () => axios.get('/authority/qua/mpk');
    Promise.all([initIp(), initQua()])
      .then((results) => {
        const ip = results[0];
        const qua = results[1];
        console.log(ip.data, qua.data);
        setPublicKey({
          InnerProduct: ip.data,
          Quadratic: qua.data
        });
        toast({
          position: 'top-right',
          description: 'succeed',
          status: 'success'
        });
      }).catch(err => {
        console.log(err.message);
        toast({
          description: err.message || 'error',
          status: 'error'
        });
      }).finally(() => {
        setRetrieving(false);
      });
    console.log(type);
    setPublicKey('Public key');
  };
  const handleEncrypt = async () => {
    console.log('handleEncrypt');
    if (type === 'InnerProduct') {
      if (!publicKey[type].v) {
        toast({
          description: 'Please retrieve publick key',
          status: 'error',
          position: 'top-right'
        });
        return;
      }
    } else {
      if (!publicKey[type].g1s) {
        toast({
          description: 'Please init or retrieve publick key',
          status: 'error',
          position: 'top-right'
        });
        return;
      }
    }
    setUploading(true);
    try {
      // const addPublicKey = () => axios.post(`/owner/${PATH[type]}/pk`, publicKey[type]);

      const rawDataParams = type === 'InnerProduct' ? {
        rawdata: {
          d: rawDataInput
        },
        pk: publicKey[type]
      } : {
        rawdata: {
          x: rawDataInput,
          y: rawDataYInput
        },
        pk: publicKey[type]
      };
      // eslint-disable-next-line no-unused-vars
      // const encrypt = () => axios.post(`/owner/${PATH[type]}/encrypt`, rawDataParams);
      // const encrypt = () => axios.post(`/owner/${PATH[type]}/encrypt`);
      // const getCipher = () => axios.get(`/owner/${PATH[type]}/getipcipher`);

      // const results = await Promise.all([
      //   // addPublicKey(),
      //   // addRawData(),
      //   encrypt(),
      //   getCipher()
      // ]);
      // console.log(results);
      const cipher = await axios.post(`/owner/${PATH[type]}/encrypt`, rawDataParams);
      // const result = await axios.get(`/owner/${PATH[type]}/getipcipher`);
      console.log(cipher);
      const uploadData = {
        number: Number(dataId),
        receiver: address
      };
      if (type === 'InnerProduct') {
        uploadData.ciphers = { ...cipher.data[0], ...cipher.data[1] };
      } else {
        uploadData.ciphers = { ...cipher.data };
      }
      console.log(uploadData);

      setCiphertext(uploadData.ciphers);

      await axios.post(`/authority/${PATH[type]}/input`, uploadData);
      toast({
        status: 'success',
        description: 'succeed',
        position: 'top-right'
      });
    } catch (err) {
      console.log(err.message);
      toast({
        status: 'error',
        description: err.message,
        position: 'top-right'
      });
    }
    setUploading(false);
  };
  return (
    <Flex w='100%' direction='column' p='1rem' alignItems='center' background='gray.50' borderRadius='1rem'>
      <Heading>Data Owner</Heading>

      <Flex w='60%' direction='column' mt='1rem'>

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
        <Stack spacing={3}>
          <Alert status={!publicKey[type] ? 'info' : 'success'}>
            <AlertDescription display='block'>
              {!publicKey[type] ? 'Waiting for retrieve.' : (
                <span>
                  {type === 'InnerProduct' ? publicKey[type].v : (
                    <>
                      <p>{publicKey[type].g1s}</p>
                      <p>{publicKey[type].g2t}</p>
                    </>
                  )}
                </span>
              ) }
            </AlertDescription>
          </Alert>

          <Button colorScheme='pink' isLoading={retrieving} onClick={handleRetrieve}>Retrieve Public Key</Button>
          <Input
            isInvalid={!!rawDataErr}
            errorBorderColor='crimson'
            value={rawData}
            onChange={(e) => setRawData(e.target.value)}
            background='white'
            placeholder='Please enter your Raw data, seperate with "," e.g. 1,2'/>
          {
            !!rawDataErr && (
              <Alert status={'error'}>
                <AlertDescription display='block'>
                  {rawDataErr}
                </AlertDescription>
              </Alert>
            )
          }
          {
            type === 'Quadratic' && (
              <>
                <Input
                  isInvalid={!!rawDataYErr}
                  errorBorderColor='crimson'
                  value={rawDataY}
                  onChange={(e) => setRawDataY(e.target.value)}
                  background='white'
                  placeholder='Please enter your Raw data, seperate with "," e.g. 1,2'/>
                {
                  !!rawDataYErr && (

                    <Alert status={'error'}>
                      <AlertDescription display='block'>
                        {rawDataYErr}
                      </AlertDescription>
                    </Alert>
                  )
                }
              </>
            )
          }
          <Input
            isInvalid={!!dataIdErr}
            errorBorderColor='crimson'
            value={dataId}
            onChange={(e) => setDataId(e.target.value)}
            background='white'
            placeholder='Please enter your Data id'/>
          {
            !!dataIdErr && (

              <Alert status={'error'}>
                <AlertDescription>
                  {dataIdErr}
                </AlertDescription>
              </Alert>
            )
          }
          <Input
            isInvalid={!!addressErr}
            errorBorderColor='crimson'
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            background='white'
            placeholder='Please enter receipt address'/>
          {
            !!addressErr && (

              <Alert status={'error'}>
                <AlertDescription>
                  {addressErr}
                </AlertDescription>
              </Alert>
            )
          }
          <Button disabled={disabledEncrypt} isLoading={uploading} colorScheme='pink' onClick={handleEncrypt}>Encrypt and Upload</Button>
          {
            ciphertext &&
            <Alert status='success'>
              <Box flex='1'>
                <AlertTitle>Encrypted Cipher</AlertTitle>
                <AlertDescription w='100%'>
                  {JSON.stringify(ciphertext)}
                </AlertDescription>
              </Box>
            </Alert>}
        </Stack>
      </Flex>
    </Flex>
  );
};
