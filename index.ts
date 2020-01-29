import * as reverse from 'buffer-reverse'
import * as CryptoJS from 'crypto-js'
import * as treeify from 'treeify'

interface Options {
  /** If set to `true`, an odd node will be duplicated and combined to make a pair to generate the layer hash. */
  duplicateOdd: boolean
  /** If set to `true`, the leaves will hashed using the set hashing algorithms. */
  hashLeaves: boolean
  /** If set to `true`, constructs the Merkle Tree using the [Bitcoin Merkle Tree implementation](http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html). Enable it when you need to replicate Bitcoin constructed Merkle Trees. In Bitcoin Merkle Trees, single nodes are combined with themselves, and each output hash is hashed again. */
  isBitcoinTree: boolean
  /** If set to `true`, the leaves will be sorted. */
  sortLeaves: boolean
  /** If set to `true`, the hashing pairs will be sorted. */
  sortPairs: boolean
  /** If set to `true`, the leaves and hashing pairs will be sorted. */
  sort: boolean
}


/**
 * Class reprensenting a Merkle Tree
 * @namespace MerkleTree
 */
export class MerkleTree {
  duplicateOdd: boolean
  hashAlgo: (value: any) => any
  hashLeaves: boolean
  isBitcoinTree: boolean
  leaves: any[]
  layers: any[]
  sortLeaves: boolean
  sortPairs: boolean
  sort: boolean

  /**
   * @desc Constructs a Merkle Tree.
   * All nodes and leaves are stored as Buffers.
   * Lonely leaf nodes are promoted to the next level up without being hashed again.
   * @param {Buffer[]} leaves - Array of hashed leaves. Each leaf must be a Buffer.
   * @param {Function} hashAlgorithm - Algorithm used for hashing leaves and nodes
   * @param {Object} options - Additional options
   * @example
   *```js
   *const MerkleTree = require('merkletreejs')
   *const crypto = require('crypto')
   *
   *function sha256(data) {
   *  // returns Buffer
   *  return crypto.createHash('sha256').update(data).digest()
   *}
   *
   *const leaves = ['a', 'b', 'c'].map(x => keccak(x))
   *
   *const tree = new MerkleTree(leaves, sha256)
   *```
   */
  constructor(leaves, hashAlgorithm, options: Options = {} as any) {
    this.isBitcoinTree = !!options.isBitcoinTree
    this.hashLeaves = !!options.hashLeaves
    this.sortLeaves = !!options.sortLeaves
    this.sortPairs = !!options.sortPairs

    this.sort = !!options.sort
    if (this.sort) {
      this.sortLeaves = true
      this.sortPairs = true
    }

    this.duplicateOdd = !!options.duplicateOdd
    this.hashAlgo = bufferifyFn(hashAlgorithm)
    if (this.hashLeaves) {
      leaves = leaves.map(this.hashAlgo)
    }

    this.leaves = leaves.map(bufferify)
    if (this.sortLeaves) {
      this.leaves = this.leaves.sort(Buffer.compare)
    }

    this.layers = [this.leaves]
    this.createHashes(this.leaves)
  }

  // TODO: documentation
  createHashes(nodes) {
    while (nodes.length > 1) {

      const layerIndex = this.layers.length

      this.layers.push([])

      for (let i = 0; i < nodes.length; i += 2) {

        if (i + 1 === nodes.length) {
          if (nodes.length % 2 === 1) {
            let data = nodes[nodes.length - 1]
            let hash = data

            // is bitcoin tree
            if (this.isBitcoinTree) {
              // Bitcoin method of duplicating the odd ending nodes
              data = Buffer.concat([reverse(data), reverse(data)])
              hash = this.hashAlgo(data)
              hash = reverse(this.hashAlgo(hash))

              this.layers[layerIndex].push(hash)
              continue
            } else {
              if (!this.duplicateOdd) {
                this.layers[layerIndex].push(nodes[i])
                continue
              }
            }
          }

        }

        const left = nodes[i]
        const right = i + 1 == nodes.length ? left : nodes[i + 1];
        let data = null
        let combined = null

        if (this.isBitcoinTree) {
          combined = [reverse(left), reverse(right)]
        } else {
          combined = [left, right]
        }

        if (this.sortPairs) {
          combined.sort(Buffer.compare)
        }

        data = Buffer.concat(combined)

        let hash = this.hashAlgo(data)

        // double hash if bitcoin tree
        if (this.isBitcoinTree) {
          hash = reverse(this.hashAlgo(hash))
        }

        this.layers[layerIndex].push(hash)
      }

      nodes = this.layers[layerIndex]
    }
  }

  /**
   * verifyPartialTree
   * @desc Constructs Partial Merkle Tree
   * @param {Buffer[]} targetNodes - leaves that are to be provided to the partial merkle tree
   * @return {Buffer[][]}
   * @example
   *```js
   *const partialTree = tree.createPartialTree(leaves)
   *```
   */
  createPartialTree(targetNodes) {
    // first we make a quick pass to transform our leaves
    var targetNodeIndex = 0;
    var partialTree = [];
    partialTree.push([]);

    for (let i = 0; i < this.leaves.length; i += 2) {
        if (i + 1 === this.leaves.length) {
            partialTree[0].push({ type: "CHILD", data: null });
        } else {
            let left = this.leaves[i];
            let right = i + 1 == this.leaves.length ? left : this.leaves[i + 1];

            let leftTargetNodeFound = false;
            let rightTargetNodeFound = false;

            for (var k = 0; k < targetNodes.length; k++) {
                if (Buffer.compare(targetNodes[k], left) == 0) {
                    partialTree[0].push({ type: "TARGET", data: targetNodeIndex });
                    targetNodeIndex++;
                    leftTargetNodeFound = true;
                }
                if (Buffer.compare(targetNodes[k], right) == 0) {
                    if (!leftTargetNodeFound) {
                        partialTree[0].push({ type: "HASH", data: left });
                    }
                    partialTree[0][i+1] = ({ type: "TARGET", data: targetNodeIndex });
                    targetNodeIndex++;
                    rightTargetNodeFound = true;
                }
            }
            if (!leftTargetNodeFound && !rightTargetNodeFound) {
                partialTree[0].push({ type: "CHILD", data: null });
                partialTree[0].push({ type: "CHILD", data: null });
            }
            if (leftTargetNodeFound && !rightTargetNodeFound) {
                partialTree[0].push({ type: "HASH", data: right });
            }
        }
    }

    // add additional layers on top
    let nodes = partialTree[0];
    while (nodes.length > 1) {
        let partialTreeIndex = partialTree.length;
        partialTree.push([]);

        for (var i = 0; i < nodes.length; i += 2) {
            if (i + 1 === nodes.length) {
                // push an empty buffer, knock this up further the stack
                partialTree[partialTreeIndex].push({ type: "CHILD", data: null });
            } else {
                let index = i / 2 | 0;
                var left = nodes[i];
                var right = i + 1 == nodes.length ? left : nodes[i + 1];

                if (left.type == "CHILD" && right.type == "CHILD") {
                    partialTree[partialTreeIndex].push({
                        type: "CHILD",
                        data: null
                    });
                }

                if (left.type == "EMPTY" && right.type == "EMPTY") {
                    partialTree[partialTreeIndex].push({
                        type: "EMPTY",
                        data: null
                    });
                }

                if ((left.type == "HASH" || left.type == "TARGET") &&
                    (right.type == "HASH" || right.type == "TARGET")) {
                    partialTree[partialTreeIndex].push({
                        type: "EMPTY",
                        data: null
                    });
                }

                if ((left.type == "HASH" && right.type == "EMPTY") ||
                    (right.type == "HASH" && right.type == "EMPTY")) {
                    partialTree[partialTreeIndex].push({
                        type: "EMPTY",
                        data: null
                    });
                }

                if ((left.type == "CHILD" && right.type == "EMPTY")) {
                    partialTree[partialTreeIndex-1][i] = {
                        type: "HASH",
                        data: this.layers[partialTreeIndex-1][i]
                    }
                    partialTree[partialTreeIndex].push({
                        type: "EMPTY",
                        data: null
                    });
                }

                if ((left.type == "EMPTY" && right.type == "CHILD")) {
                    partialTree[partialTreeIndex-1][i+1] = {
                        type: "HASH",
                        data: this.layers[partialTreeIndex-1][i+1]
                    }
                    partialTree[partialTreeIndex].push({
                        type: "EMPTY",
                        data: null
                    });
                }
            }
        }

        nodes = partialTree[partialTreeIndex];
    }

    return partialTree;
  }

  /**
   * verifyPartialTree
   * @desc Returns true if the partialTree (multiple array of hashes) can hash the
   * tree to the merkle root.
   * @param {Object[]}
   * @param {Buffer[]}
   * @param {Buffer}
   * @return {booean}
   * @example
   *```js
   *const partialTree = tree.createPartialTree(leaves)
   const areLeavesValid = tree.verifyPartialTree(partialTree, leaves, tree.getRoot())
   *```
   */
  verifyPartialTree(partialTree, leaves, root) {
    for (let j = 0; j < partialTree.length; j++) {
      var nodes = partialTree[j];
      if (nodes.length == 1) {
        return Buffer.compare(nodes[0].data, root) == 0;
      }
      for (var i = 0; i < nodes.length; i += 2) {
        if (i + 1 !== nodes.length) {
          var index = i / 2 | 0;
          var left = nodes[i];
          var right = i + 1 == nodes.length ? left : nodes[i + 1];
          if (left.type == "CHILD" && right.type == "CHILD") { }
          else {
            let left_data = left.type == "HASH" ? left.data : leaves[left.data];
            let right_data = right.type == "HASH" ? right.data : leaves[right.data];

            var combined = [left_data, right_data];
            var buffered = Buffer.concat(combined);
            var data = this.hashAlgo(buffered);
            partialTree[j+1][index] = {
              type: "HASH",
              data: data
            };
          }
        }
      }
    }
  }

  /**
   * getLeaves
   * @desc Returns array of leaves of Merkle Tree.
   * @return {Buffer[]}
   * @example
   *```js
   *const leaves = tree.getLeaves()
   *```
   */
  getLeaves() {
    return this.leaves
  }

  /**
   * getLayers
   * @desc Returns array of all layers of Merkle Tree, including leaves and root.
   * @return {Buffer[]}
   * @example
   *```js
   *const layers = tree.getLayers()
   *```
   */
  getLayers() {
    return this.layers
  }

  /**
   * getRoot
   * @desc Returns the Merkle root hash as a Buffer.
   * @return {Buffer}
   * @example
   *```js
   *const root = tree.getRoot()
   *```
   */
  getRoot() {
    return this.layers[this.layers.length - 1][0] || Buffer.from([])
  }

  // TODO: documentation
  getHexRoot() {
    return bufferToHex(this.getRoot())
  }

  /**
   * getProof
   * @desc Returns the proof for a target leaf.
   * @param {Buffer} leaf - Target leaf
   * @param {Number} [index] - Target leaf index in leaves array.
   * Use if there are leaves containing duplicate data in order to distinguish it.
   * @return {Object[]} - Array of objects containing a position property of type string
   * with values of 'left' or 'right' and a data property of type Buffer.
   *@example
   * ```js
   *const proof = tree.getProof(leaves[2])
   *```
   *
   * @example
   *```js
   *const leaves = ['a', 'b', 'a'].map(x => keccak(x))
   *const tree = new MerkleTree(leaves, keccak)
   *const proof = tree.getProof(leaves[2], 2)
   *```
   */
  getProof(leaf, index?) {
    leaf = bufferify(leaf)
    const proof = []

    if (typeof index !== 'number') {
      index = -1

      for (let i = 0; i < this.leaves.length; i++) {
        if (Buffer.compare(leaf, this.leaves[i]) === 0) {
          index = i
        }
      }
    }

    if (index <= -1) {
      return []
    }

    if (this.isBitcoinTree && index === (this.leaves.length - 1)) {
      // Proof Generation for Bitcoin Trees

      for (let i = 0; i < this.layers.length - 1; i++) {
        const layer = this.layers[i]
        const isRightNode = index % 2
        const pairIndex = (isRightNode ? index - 1 : index)

        if (pairIndex < layer.length) {
          proof.push({
            data: layer[pairIndex]
          })
        }

        // set index to parent index
        index = (index / 2) | 0
      }

      return proof
    } else {

      // Proof Generation for Non-Bitcoin Trees

      for (let i = 0; i < this.layers.length; i++) {
        const layer = this.layers[i]
        const isRightNode = index % 2
        const pairIndex = (isRightNode ? index - 1 : index + 1)

        if (pairIndex < layer.length) {
          proof.push({
            position: isRightNode ? 'left' : 'right',
            data: layer[pairIndex]
          })
        }

        // set index to parent index
        index = (index / 2) | 0

      }

      return proof
    }
  }

  // TODO: documentation
  getHexProof(leaf, index?) {
    return this.getProof(leaf, index).map(x => bufferToHex(x.data))
  }

  /**
   * verify
   * @desc Returns true if the proof path (array of hashes) can connect the target node
   * to the Merkle root.
   * @param {Object[]} proof - Array of proof objects that should connect
   * target node to Merkle root.
   * @param {Buffer} targetNode - Target node Buffer
   * @param {Buffer} root - Merkle root Buffer
   * @return {Boolean}
   * @example
   *```js
   *const root = tree.getRoot()
   *const proof = tree.getProof(leaves[2])
   *const verified = tree.verify(proof, leaves[2], root)
   *```
   */
  verify(proof, targetNode, root) {
    let hash = bufferify(targetNode)
    root = bufferify(root)

    if (!Array.isArray(proof) ||
      !proof.length ||
      !targetNode ||
      !root) {
      return false
    }

    for (let i = 0; i < proof.length; i++) {
      const node = proof[i]
      let data = null
      let isLeftNode = null

      // NOTE: case for when proof is hex values only
      if (typeof node === 'string') {
        data = bufferify(node)
        isLeftNode = true
      } else {
        data = node.data
        isLeftNode = (node.position === 'left')
      }

      const buffers = []

      if (this.isBitcoinTree) {
        buffers.push(reverse(hash))

        buffers[isLeftNode ? 'unshift' : 'push'](reverse(data))

        hash = this.hashAlgo(Buffer.concat(buffers))
        hash = reverse(this.hashAlgo(hash))

      } else {
        if (this.sortPairs) {
          if (Buffer.compare(hash, data) === -1) {
            buffers.push(hash, data)
            hash = this.hashAlgo(Buffer.concat(buffers));
          } else {
            buffers.push(data, hash)
            hash = this.hashAlgo(Buffer.concat(buffers));
          }
        } else {
          buffers.push(hash);
          buffers[isLeftNode ? 'unshift' : 'push'](data);
          hash = this.hashAlgo(Buffer.concat(buffers));
        }
      }
    }

    return Buffer.compare(hash, root) === 0
  }

  // TODO: documentation
  getLayersAsObject() {
    const layers = this.getLayers().map(x => x.map(x => x.toString('hex')))
    const objs = []
    for (let i = 0; i < layers.length; i++) {
      const arr = []
      for (let j = 0; j < layers[i].length; j++) {
        const obj = { [layers[i][j]]: null }
        if (objs.length) {
          obj[layers[i][j]] = {}
          const a = objs.shift()
          const akey = Object.keys(a)[0]
          obj[layers[i][j]][akey] = a[akey]
          if (objs.length) {
            const b = objs.shift()
            const bkey = Object.keys(b)[0]
            obj[layers[i][j]][bkey] = b[bkey]
          }
        }

        arr.push(obj)
      }

      objs.push(...arr)
    }

    return objs[0]
  }

  // TODO: documentation
  print() {
    MerkleTree.print(this)
  }

  // TODO: documentation
  toTreeString() {
    const obj = this.getLayersAsObject()
    return treeify.asTree(obj, true)
  }

  // TODO: documentation
  toString() {
    return this.toTreeString()
  }

  // TODO: documentation
  static bufferify(x) {
    return bufferify(x)
  }

  // TODO: documentation
  static print(tree) {
    console.log(tree.toString())
  }
}

function bufferToHex(value: Buffer) {
  return '0x' + value.toString('hex')
}

function bufferify(x) {
  if (!Buffer.isBuffer(x)) {
    // crypto-js support
    if (typeof x === 'object' && x.words) {
      return Buffer.from(x.toString(CryptoJS.enc.Hex), 'hex')
    } else if (isHexStr(x)) {
      return Buffer.from(x.replace(/^0x/, ''), 'hex')
    } else if (typeof x === 'string') {
      return Buffer.from(x)
    }
  }

  return x
}

function bufferifyFn(f) {
  return function (x) {
    const v = f(x)
    if (Buffer.isBuffer(v)) {
      return v
    }

    if (isHexStr(v)) {
      return Buffer.from(v, 'hex')
    }

    // crypto-js support
    return Buffer.from(f(CryptoJS.enc.Hex.parse(x.toString('hex'))).toString(CryptoJS.enc.Hex), 'hex')
  }
}

function isHexStr(v) {
  return (typeof v === 'string' && /^(0x)?[0-9A-Fa-f]*$/.test(v))
}

export default MerkleTree
