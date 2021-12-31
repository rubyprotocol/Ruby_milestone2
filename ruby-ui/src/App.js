import React, { useState, createRef } from 'react';
import { ChakraProvider } from '@chakra-ui/react';

import { Container, Dimmer, Loader, Grid, Message, Segment, Menu } from 'semantic-ui-react';

import 'semantic-ui-css/semantic.min.css';

import { SubstrateContextProvider, useSubstrate } from './substrate-lib';
import { DeveloperConsole } from './substrate-lib/components';

// import AccountSelector from './components/AccountSelector';
// import Balances from './Balances';
// import BlockNumber from './BlockNumber';
// import Events from './Events';
// import Interactor from './Interactor';
// import Metadata from './Metadata';
// import NodeInfo from './NodeInfo';
// import TemplateModule from './TemplateModule';
// import Transfer from './Transfer';
// import Upgrade from './Upgrade';
import { KeyAuthority } from './pages/KeyAuthority';
import { Owner } from './pages/Owner';
import { Purchaser } from './pages/Purchaser';

function Main () {
  const [activeItem, setActiveItem] = useState('Key Authority');
  const { apiState, keyringState, apiError } = useSubstrate();

  const loader = text =>
    <Dimmer active>
      <Loader size='small'>{text}</Loader>
    </Dimmer>;

  const message = err =>
    <Grid centered columns={2} padded>
      <Grid.Column>
        <Message negative compact floating
          header='Error Connecting to Substrate'
          content={`${err}`}
        />
      </Grid.Column>
    </Grid>;

  if (apiState === 'ERROR') return message(apiError);
  else if (apiState !== 'READY') return loader('Connecting to Substrate');

  if (keyringState !== 'READY') {
    return loader('Loading accounts (please review any extension\'s authorization)');
  }

  const contextRef = createRef();
  const handleItemClick = (e, { name }) => setActiveItem(name);

  return (
    <div ref={contextRef}>
      <Segment inverted>
        <Container>
          <Menu
            attached='top'
            inverted
            secondary
          >
            <Menu.Item>
              <h1 style={{ marginRight: '1rem' }}>Ruby Protocol</h1>
            </Menu.Item>
            <Menu.Item
              name='Key Authority'
              active={activeItem === 'Key Authority'}
              onClick={handleItemClick}
              color='pink'
            />
            <Menu.Item
              name='Owner'
              active={activeItem === 'Owner'}
              onClick={handleItemClick}
              color='pink'
            />
            <Menu.Item
              name='Purchaser'
              color='pink'
              active={activeItem === 'Purchaser'}
              onClick={handleItemClick}
            />

            {/* <Menu.Menu position='right' style={{ alignItems: 'center' }}>
              <AccountSelector setAccountAddress={setAccountAddress} />
            </Menu.Menu> */}
          </Menu>
        </Container>
      </Segment>
      <Container>
        {activeItem === 'Key Authority' && (<KeyAuthority/>)}
        {activeItem === 'Owner' && (<Owner/>)}
        {activeItem === 'Purchaser' && (<Purchaser/>)}
      </Container>
      <DeveloperConsole />
    </div>
  );
}

export default function App () {
  return (
    <ChakraProvider>
      <SubstrateContextProvider>
        <Main />
      </SubstrateContextProvider>
    </ChakraProvider>
  );
}
