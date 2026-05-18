// Regression test for CVE-2022-21803: nconf memory engine prototype pollution
// This test ensures that the vulnerability is fixed in nconf@0.11.4+

const nconf = require('nconf');
const assert = require('assert');

describe('nconf memory engine prototype pollution protection', function() {
  
  it('should prevent prototype pollution via constructor key', function() {
    const config = new nconf.Provider().use('memory');
    
    // Attempt to pollute the prototype using the constructor pattern
    config.set('constructor:prototype:polluted', true);
    
    // Verify the prototype is not polluted
    assert.strictEqual(({}).polluted, undefined, 'Prototype pollution via constructor should be prevented');
  });
  
  it('should prevent prototype pollution via __proto__ key', function() {
    const config = new nconf.Provider().use('memory');
    
    // Attempt to pollute via __proto__
    config.set('__proto__:polluted', true);
    
    // Verify the prototype is not polluted
    assert.strictEqual(({}).polluted, undefined, 'Prototype pollution via __proto__ should be prevented');
  });
  
  it('should prevent prototype pollution via prototype key', function() {
    const config = new nconf.Provider().use('memory');
    
    // Attempt to pollute via prototype
    config.set('prototype:polluted', true);
    
    // Verify the prototype is not polluted
    assert.strictEqual(({}).polluted, undefined, 'Prototype pollution via prototype should be prevented');
  });
  
  it('should allow normal nested property setting', function() {
    const config = new nconf.Provider().use('memory');
    
    // Normal usage should work
    config.set('app:name', 'test-app');
    config.set('app:version', '1.0.0');
    
    assert.strictEqual(config.get('app:name'), 'test-app');
    assert.strictEqual(config.get('app:version'), '1.0.0');
  });
});
