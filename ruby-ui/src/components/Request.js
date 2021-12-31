import React from 'react';
import axios from 'axios';

export const http = axios.create({
  baseURL: '',
  timeout: 10000
  // headers: {
  //   'X-API-KEY': 'a47e9b96f1ca464792fb00e673164afc'
  // }
});
export const RequestProvider = () => {
  return (
    <div>

    </div>
  );
};
