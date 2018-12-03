'use strict';

var _ = require('lodash');
var inherits = require('inherits');
var Input = require('./input');
var Output = require('../output');
var $ = require('../../util/preconditions');

var Script = require('../../script');
var Signature = require('../../crypto/signature');
var BufferUtil = require('../../util/buffer');
var TransactionSignature = require('../signature');
var Opcode = require('../../opcode');
var Hash = require('../../../lib/crypto/hash');
var ECDSA = require('../../../lib/crypto/ecdsa');

/**
 * @constructor
 */
function ScriptHashInput(input, msg, pubkey) {
  Input.apply(this, arguments);
  // var bytes = Random.getRandomBuffer(32);
  this.msg = msg;
  this.publicKey = pubkey;
  this.redeemScript = this._buildCheckDataSigOut();
}

inherits(ScriptHashInput, Input);

ScriptHashInput.prototype._buildCheckDataSigOut = function() {
  let script = new Script();
  script.add(this.msg).add(this.publicKey.toBuffer()).add(Opcode.OP_CHECKDATASIG);
  return script;
};

ScriptHashInput.prototype._getSig = function(privateKey) {
  var ecdsa = new ECDSA();
  ecdsa.hashbuf = Hash.sha256(this.msg);
  ecdsa.privkey = privateKey;
  ecdsa.pubkey = privateKey.toPublicKey();
  ecdsa.signRandomK();
  ecdsa.calci();
  return ecdsa.sig;
};

ScriptHashInput.prototype._buildCheckDataSigIn = function(signature) {
  let script = new Script();
  script.add(signature).add(this.redeemScript.toBuffer());
  return script;
};

ScriptHashInput.prototype.toObject = function() {
  var obj = Input.prototype.toObject.apply(this, arguments);
  obj.publicKey = this.publicKey.toString();
  obj.signature = this._serializeSignature();
  return obj;
};

ScriptHashInput.prototype._serializeSignature = function() {
  return this.signature.toObject();
};

ScriptHashInput.prototype.getSignatures = function(transaction, privateKey, index, sigtype) {

  $.checkState(this.output instanceof Output);
  sigtype = (Signature.SIGHASH_ALL |  Signature.SIGHASH_FORKID);

  return [new TransactionSignature({
    publicKey: privateKey.publicKey,
    prevTxId: this.prevTxId,
    outputIndex: this.outputIndex,
    inputIndex: index,
    signature: this._getSig(privateKey),
    sigtype: sigtype
  })];
};

ScriptHashInput.prototype.addSignature = function(transaction, signature) {
  this.signature = signature;
  this.setScript(this._buildCheckDataSigIn(
    signature.signature.toDER(),
  ));
  return this;
};

ScriptHashInput.prototype._createSignatures = function() {
  return this._getSig().toDER();
};

ScriptHashInput.prototype.clearSignatures = function() {
  this.signature = null;
  this.setScript(Script.empty());
  return this;
};
ScriptHashInput.prototype.isFullySigned = function() {
  return true;
};


module.exports = ScriptHashInput;
