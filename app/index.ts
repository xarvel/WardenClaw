// SPDX-License-Identifier: GPL-3.0-or-later
import { registerRootComponent } from 'expo';

import App from './App';
import { registerBackgroundTask } from './src/core/background';

// Headless task of the background service (new card notifications): registered before the UI,
// because the service can start the process without a screen.
registerBackgroundTask();

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
