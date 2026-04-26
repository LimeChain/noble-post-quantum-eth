import { should } from '@paulmillr/jsbt/test.js';
import './falcon-eth.test.ts';
import './keccak-prg.test.ts';
import './ml-dsa-eth.test.ts';

should.runWhen(import.meta.url);
