/* eslint-disable no-unused-vars */
import React, { useCallback, useState } from 'react';
import axios from 'axios';
import { Heading, HStack, useRadioGroup, Stack, AlertTitle, Box, Flex, Button, Input, useToast, Alert, AlertDescription } from '@chakra-ui/react';
import { useSubstrate } from '../substrate-lib';
import { RadioCard } from '../components/RadioCard';
import { PATH } from './Owner';

export const KeyAuthority = () => {
  const { api, apiState, keyring, keyringState } = useSubstrate();
  const accountPair =
    keyringState === 'READY' &&
    keyring.getPair(process.env.REACT_APP_AUTHORITY_ADDRESS);

  const [receiver, setReceiver] = useState('');

  const toast = useToast();
  const [purchaserId, setPurchaserId] = useState('');
  const [dataId, setDataId] = useState('');
  const [VK, setVK] = useState('');
  const [Proof, setProof] = useState('');
  const [deriveContent, setDeriveContent] = useState('');
  const [generated, setGenerated] = useState(false);
  const [transferred, setTransferred] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [transfering, setTransfering] = useState(false);
  const [verifing, setVerifing] = useState(false);
  const [vking, setVking] = useState(false);
  const [proofing, setProofing] = useState(false);
  const [vkUpdating, setVkUpdating] = useState(false);
  const [initing, setIniting] = useState(false);
  const [type, setType] = useState('InnerProduct');
  const [vkBlockhash, setVkBlockhash] = useState('');
  const [proofBlockhash, setProofBlockhash] = useState('');

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

  const handleInit = () => {
    setIniting(true);
    const initIp = () => {
      return axios.get('/authority/ip/init');
    };
    const initQua = () => {
      return axios.get('/authority/qua/init');
    };
    Promise.all([initIp(), initQua()])
      .then((results) => {
        const ip = results[0];
        const qua = results[1];
        toast({
          description: 'Init successful',
          status: 'success',
          position: 'top-right'
        });
      }).catch(err => {
        console.log(err.message);
        toast({
          position: 'top-right',
          description: err.message || 'error',
          status: 'error'
        });
      }).finally(() => {
        setIniting(false);
      });
  };

  const handleGenerate = async () => {
    setGenerating(true);
    const params = {
      buyernumber: Number(purchaserId),
      ciphernumber: Number(dataId)
    };
    axios.post(`/authority/${PATH[type]}/derive`, params).then(res => {
      console.log(res.data);
      const { data } = res;
      setGenerated(true);
      let receiver,
        vkData,
        proofData;
      if (type === 'InnerProduct') {
        receiver = data[0]['owner account'];
        vkData = data[1]['vk:'];
        proofData = data[1]['substrate proof:'];
        console.log(data[1], vkData, proofData);
      } else {
        receiver = res.data[1]['owner account'];
        vkData = data[3]['vk:'];
        proofData = data[3]['substrate proof:'];
        console.log(vkData, proofData);
      }
      setDeriveContent(data);
      setReceiver(receiver);
      setVK(vkData);
      setProof(proofData);
      toast({
        position: 'top-right',
        status: 'success',
        description: 'Generate successful'
      });
    }).catch(err => {
      toast({
        position: 'top-right',
        status: 'error',
        description: err.message
      });
    }).finally(() => {
      setGenerating(false);
    });
  };

  const handleTransfer = useCallback(() => {
    return new Promise((resolve, reject) => {
      if (!api) {
        reject(new Error('Please connect api'));
        return;
      }
      if (apiState !== 'READY') {
        reject(new Error('Api is not ready'));
        return;
      }
      let unsub = null;
      const asyncFn = async () => {
        try {
          setTransfering(true);
          const amount = 1000000000000; // 1 DOT

          console.log(accountPair, receiver);

          unsub = await api.tx.balances
            .transfer(receiver, amount)
            .signAndSend(accountPair, ({ events = [], status }) => {
              console.log(status);

              if (status.isReady) {
                toast({
                  description: 'Transferring...',
                  status: 'info',
                  duration: null,
                  id: 'waiting',
                  position: 'top-right'
                });
              } else if (status.isInBlock || status.isFinalized) {
                events.forEach(async ({ event }) => {
                  console.log(event);

                  if (event.method === 'ExtrinsicSuccess') {
                    setTransferred(true);
                    resolve('Transfer successful');
                    toast({
                      status: 'success',
                      description: 'Transfer successful',
                      position: 'top-right'
                    });
                  } else if (event.method === 'ExtrinsicFailed') {
                    reject(new Error('Transaction failed.'));
                  }
                });
                toast.close('waiting');

                setVerifing(false);
                setTransfering(false);
                unsub();
              }
            });
        } catch (err) {
          reject(new Error(err.message || err.tostring() || 'Error occured while transaction.'));

          setVerifing(false);
          setTransfering(false);
          unsub && unsub();
        }
      };

      asyncFn();

      return () => {
        unsub && unsub();
      };
    });
  }, [accountPair, api, apiState, receiver, toast]);

  const handleGenerateVK = () => {
    setVking(true);
    setVK('vk');
    setVking(false);
  };

  const handleGenerateProof = () => {
    setProofing(true);
    setProof('vk');
    setProofing(false);
  };
  const handleSetVK = useCallback(() => {
    let unsub = null;
    if (apiState === 'READY') {
      const asyncFn = async () => {
        try {
          if (api) {
            setVkUpdating(true);

            unsub = await api.tx.zeropool
              .setVk(VK)
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
                      setVkBlockhash(status.asInBlock.toHex());
                    } else if (event.method === 'ExtrinsicFailed') {
                      toast({
                        description: 'Transaction failed.',
                        position: 'top-right',
                        status: 'error'
                      });
                    }
                  });
                  toast.close('waiting');

                  setVkUpdating(false);
                  unsub();
                }
              });
          }
        } catch (err) {
          toast({
            description: err.message || err.tostring() || 'Error occured while transaction.',
            position: 'top-right',
            status: 'error'
          });

          setVkUpdating(false);
          unsub && unsub();
        }
      };

      asyncFn();
    }

    return () => {
      unsub && unsub();
    };
  }, [VK, api, apiState, toast, accountPair]);
  const handleVerify = useCallback(() => {
    let unsub = null;
    if (apiState === 'READY') {
      const asyncFn = async () => {
        try {
          if (api) {
            setVerifing(true);

            unsub = await api.tx.zeropool
              .testGroth16Verify(Proof)
              .signAndSend(accountPair, ({ events = [], status }) => {
                console.log(status);

                if (status.isReady) {
                  toast({
                    description: 'Verifing...',
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
                        description: 'Verify successful',
                        position: 'top-right'
                      });

                      await handleTransfer();
                      setProofBlockhash(status.asInBlock.toHex());
                    } else if (event.method === 'ExtrinsicFailed') {
                      toast({
                        description: 'Transaction failed.',
                        position: 'top-right',
                        status: 'error'
                      });
                    }
                  });
                  toast.close('waiting');

                  unsub();
                }
              });
          }
        } catch (err) {
          toast({
            description: err.message || err.tostring() || 'Error occured while transaction.',
            position: 'top-right',
            status: 'error'
          });

          setVerifing(false);
          unsub && unsub();
        }
      };

      asyncFn();
    }

    return () => {
      unsub && unsub();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [Proof, api, apiState, toast, accountPair]);

  return (
    <Flex w='100%' direction='column' m='2rem' p='2rem' alignItems='center' background='gray.50' borderRadius='1rem'>
      <Heading>Key Authority</Heading>

      <Flex w='60%' direction='column' mt='1rem'>
        <Stack spacing={3}>
          <Button colorScheme='pink' isLoading={initing} onClick={handleInit}>Init SIP and SGP</Button>
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
          <Input type='number' value={dataId} onChange={(e) => setDataId(e.target.value)} background='white' placeholder='Please enter Data id'/>
          <Input type='number' value={purchaserId} onChange={(e) => setPurchaserId(e.target.value)} background='white' placeholder='Please enter Purchaser id'/>
          <Button isLoading={generating} colorScheme='pink' onClick={handleGenerate}>Derive functional key & Generate ZKP</Button>
          {
            deriveContent &&
            <Alert status='success'>
              <Box flex='1'>
                <AlertTitle>Generated Content</AlertTitle>
                <AlertDescription w='100%'>
                  {JSON.stringify(deriveContent)}
                </AlertDescription>
              </Box>
            </Alert>}
          {
            generated &&
            (
              <>
                {/* <Button colorScheme='pink' isLoading={transfering} onClick={handleTransfer}>Transfer</Button> */}
                <Alert>
                  <AlertDescription>
                    <span>VK:</span>
                    <br/>
                    {VK}
                  </AlertDescription>
                </Alert>
                <Button colorScheme='pink' isLoading={vkUpdating} onClick={handleSetVK}>Set verification key for ZKP</Button>
                {vkBlockhash && <Alert>
                  <AlertDescription>
                    <span>Blockhash:</span>
                    <br/>
                    {vkBlockhash}
                  </AlertDescription>
                </Alert>}
                <Alert>
                  <AlertDescription>
                    <span>Proof:</span>
                    <br/>
                    {Proof}
                  </AlertDescription>
                </Alert>
                <Alert>
                  <AlertDescription>
                    <span>Receiver:</span>
                    <br/>
                    {receiver}
                  </AlertDescription>
                </Alert>
                <Button colorScheme='pink' isLoading={verifing} onClick={handleVerify}>Verify the ZKP & Transfer token</Button>

                {
                  proofBlockhash && <Alert>
                    <AlertDescription>
                      <span>Blockhash:</span>
                      <br/>
                      {proofBlockhash}
                    </AlertDescription>
                  </Alert>}
              </>
            )
          }
        </Stack>
      </Flex>
    </Flex>
  );
};
