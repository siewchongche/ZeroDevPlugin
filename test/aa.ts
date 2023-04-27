import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { calcPreVerificationGas } from "../../bundler/packages/sdk/src/calcPreVerificationGas"
import { MerkleTree } from "merkletreejs";

const entryPointAddr = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

const { HashZero, AddressZero } = ethers.constants
const { arrayify, hexlify, hexConcat, hexZeroPad, hexValue, keccak256, parseEther, formatEther, defaultAbiCoder } = ethers.utils

describe("Account Abstraction", function () {

  async function deployFixture() {
    const [owner, bundler, session, paymasterSigner] = await ethers.getSigners()
    const provider = owner.provider!
    // const entryPoint = await ethers.getContractAt("EntryPoint", entryPointAddr)
    const entryPoint = await (await ethers.getContractFactory("EntryPoint")).deploy()
    const factory = await (await ethers.getContractFactory("KernelFactory")).deploy(entryPoint.address)
    const randomWallet = ethers.Wallet.createRandom().connect(provider)

    async function createEmptyUserOp(accountAddr: string, accountContractName: string) {
      const account = await ethers.getContractAt(accountContractName, accountAddr)
      const feeData = await provider.getFeeData()
      const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!.toNumber()
      const nonce = await provider.getCode(accountAddr) == "0x" ?
        0 : (await account["getNonce()"]()).toNumber()
      return {
        sender: accountAddr,
        nonce,
        initCode: "0x",
        callData: "0x",
        callGasLimit: 0,
        verificationGasLimit: 5e6,
        preVerificationGas: 0,
        maxFeePerGas: feeData.lastBaseFeePerGas!.toNumber() + maxPriorityFeePerGas,
        maxPriorityFeePerGas,
        paymasterAndData: "0x",
        signature: await owner.signMessage("0x")
      }
    }
    
    async function estimateUserOpGas(userOp: any) {
      userOp.preVerificationGas = calcPreVerificationGas(userOp)
      const err = await entryPoint.callStatic.simulateValidation(userOp).catch(e => e)
      if (!err.errorName.startsWith("ValidationResult")) {
        console.error("Error on simulateValidation:", err.errorArgs.reason)
        process.exit(1)
      }
      userOp.verificationGasLimit = err.errorArgs.returnInfo.preOpGas.toNumber()
      userOp.callGasLimit = (await provider.estimateGas({
        from: entryPoint.address, to: userOp.sender, data: userOp.callData
      })).toNumber()
      userOp.preVerificationGas = calcPreVerificationGas(userOp)
    }
    
    async function signUserOp(userOp: any) {
      const userOpHash = await entryPoint.getUserOpHash(userOp)
      userOp.signature = await owner.signMessage(arrayify(userOpHash))
    }

    return { owner, bundler, session, paymasterSigner, randomWallet, provider, entryPoint, factory, createEmptyUserOp, estimateUserOpGas, signUserOp }
  }

  async function createAccount() {
    const { owner, bundler, randomWallet, entryPoint, factory, createEmptyUserOp, estimateUserOpGas, signUserOp } = await loadFixture(deployFixture)

    const accountAddr = await factory.getAccountAddress(owner.address, 0)
    await owner.sendTransaction({ to: accountAddr, value: parseEther("1")})

    {
      const userOp = await createEmptyUserOp(accountAddr, "Kernel")
      const initCode = factory.interface.encodeFunctionData("createAccount", [owner.address, 0])
      userOp.initCode = hexConcat([factory.address, initCode])
      await estimateUserOpGas(userOp)
      await signUserOp(userOp)
      await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    }

    {
      const userOp = await createEmptyUserOp(accountAddr, "Kernel")
      userOp.callData = (await ethers.getContractFactory("Kernel")).interface.encodeFunctionData(
        "executeAndRevert",
        [randomWallet.address, parseEther("0.1"), "0x", 0]
      )
      await estimateUserOpGas(userOp)
      await signUserOp(userOp)
      await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    }

    expect(await randomWallet.getBalance()).to.eq(parseEther("0.1"))
  }

  async function sessionKey() {
    const { provider, owner, bundler, session, entryPoint, factory, createEmptyUserOp, estimateUserOpGas } = await loadFixture(deployFixture)

    await createAccount()
    const accountAddr = await factory.getAccountAddress(owner.address, 0)
    const account = await ethers.getContractAt("Kernel", accountAddr)
    const userOp = await createEmptyUserOp(accountAddr, "Kernel")
    const counter = await (await ethers.getContractFactory("Counter")).deploy()
    userOp.callData = (await ethers.getContractFactory("Kernel")).interface.encodeFunctionData(
      "executeAndRevert",
      [counter.address, 0, counter.interface.encodeFunctionData("increment"), 0]
    )
    await estimateUserOpGas(userOp)

    const merkle = new MerkleTree(
      [counter.address], keccak256, { sortPairs: true, hashLeaves: true }
    )
    const merkleRoot = "0x" + merkle.getRoot().toString("hex")

    const sessionKeyPlugin = await (await ethers.getContractFactory("ZeroDevSessionKeyPlugin")).deploy()

    // sign session key
    const ownerSig = await owner._signTypedData(
      {
        name: "Kernel",
        version: "0.0.1",
        chainId: await provider.getNetwork().then(x => x.chainId),
        verifyingContract: account.address
      },
      {
        ValidateUserOpPlugin: [
          { name: "plugin", type: "address" },
          { name: "validUntil", type: "uint48" },
          { name: "validAfter", type: "uint48" },
          { name: "data", type: "bytes" }
        ]
      },
      {
        plugin: sessionKeyPlugin.address,
        validUntil: 0,
        validAfter: 0,
        data: hexConcat([session.address, merkleRoot])
      }
    )
    // console.log(ownerSig)
    // 0xc29cded5aa8d1c449b4dc9b145d8b84fff2b4581243dad97398ac78b2043011257ad98284530e2aab04a2e475f31336de7bf18508d0c1265eb9b5fbd002532491c
    
    // get session sig
    const sessionSig = await session._signTypedData(
      {
        name: "ZeroDevSessionKeyPlugin",
        version: "0.0.1",
        chainId: await provider.getNetwork().then(x => x.chainId),
        verifyingContract: account.address
      },
      {
        Session: [
          { name: "userOpHash", type: "bytes32" },
          { name: "nonce", type: "uint256" }
        ]
      },
      {
        userOpHash: await entryPoint.getUserOpHash(userOp),
        nonce: await account["getNonce()"]()
      }
    )
    // console.log(sessionSig)
    // 0x9802b9d8c636813a2cff7ff08d733b5259c0a6c96daec20e8891c77c66d2c61347b711538fbf3791a8d693d58c51430ed891b079a66b3289f6d6d8578fed2eb71c

    // packedOwnerSig is same for each session
    const packedOwnerSig = hexConcat([
      sessionKeyPlugin.address, // address plugin - userOp.signature[0:20]
      hexZeroPad("0x00", 6), // uint48 validUntil - userOp.signature[20:26]
      hexZeroPad("0x00", 6), // uint48 validAfter - userOp.signature[26:32]
      ownerSig // bytes memory signature - userOp.signature[32:97]
    ])
    
    userOp.signature = hexConcat([
      packedOwnerSig,
      defaultAbiCoder.encode( // userOp.signature[97:]
        ["bytes", "bytes"],
        [
          hexConcat([ // data
            session.address, // address sessionKey = address(bytes20(data[0:20]))
            merkleRoot // bytes32 merkleRoot = bytes32(data[20:52])
          ]),
          hexConcat([ // signature
            hexZeroPad("0x14", 1), // leafLength (20)
            counter.address, // bytes32 leaf = keccak256(signature[1:21])
            sessionSig, // bytes calldata signature = signature[21:86]
            defaultAbiCoder.encode(["bytes[]"], [merkle.getHexProof(keccak256(counter.address))]) // bytes32[] memory proof = abi.decode(signature[86:], (bytes32[]))
          ])
        ]
      )
    ])

    await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    expect(await counter.counter()).to.eq(1)

    // get another session sig
    userOp.nonce = await account["getNonce()"]()
    const sessionSig2 = await session._signTypedData(
      {
        name: "ZeroDevSessionKeyPlugin",
        version: "0.0.1",
        chainId: await provider.getNetwork().then(x => x.chainId),
        verifyingContract: account.address
      },
      {
        Session: [
          { name: "userOpHash", type: "bytes32" },
          { name: "nonce", type: "uint256" }
        ]
      },
      {
        userOpHash: await entryPoint.getUserOpHash(userOp),
        nonce: await account["getNonce()"]()
      }
    )
    // console.log(sessionSig2)
    // 0x05f3346a4fc48d1bea903082ad646d3784d450f77e9810a6fc74f35f679a6a3014d1e3fc04ae0083f296f3db17a8a4910eabddbadea9909ac9abe3e6595411af1b

    // new signature with new session sig
    userOp.signature = hexConcat([
      packedOwnerSig,
      defaultAbiCoder.encode( // userOp.signature[97:]
        ["bytes", "bytes"],
        [
          hexConcat([ // data
            session.address, // address sessionKey = address(bytes20(data[0:20]))
            merkleRoot // bytes32 merkleRoot = bytes32(data[20:52])
          ]),
          hexConcat([ // signature
            hexZeroPad("0x14", 1), // leafLength (20)
            counter.address, // bytes32 leaf = keccak256(signature[1:21])
            sessionSig2, // bytes calldata signature = signature[21:86]
            defaultAbiCoder.encode(["bytes[]"], [merkle.getHexProof(keccak256(counter.address))]) // bytes32[] memory proof = abi.decode(signature[86:], (bytes32[]))
          ])
        ]
      )
    ])

    await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    expect(await counter.counter()).to.eq(2)
  }

  async function whitelist() {
    const { owner, bundler, provider, entryPoint, factory, createEmptyUserOp, estimateUserOpGas, signUserOp } = await loadFixture(deployFixture)

    const whitelistPlugin = await (await ethers.getContractFactory("WhitelistPlugin")).deploy()
    const randomWallet = ethers.Wallet.createRandom().connect(provider)
    const whitelistWallet = ethers.Wallet.createRandom().connect(provider)

    // await createAccount()
    await factory.createAccount(owner.address, 0)
    const accountAddr = await factory.getAccountAddress(owner.address, 0)
    const account = await ethers.getContractAt("Kernel", accountAddr)
    await owner.sendTransaction({ to: account.address, value: parseEther("1") })

    const userOp = await createEmptyUserOp(accountAddr, "Kernel")
    userOp.callData = account.interface.encodeFunctionData("executeAndRevert", [randomWallet.address, parseEther("0.1"), "0x", 0])
    await estimateUserOpGas(userOp)

    // const ownerSig = "0x"
    const ownerSig = hexConcat([
      whitelistPlugin.address, // address plugin - userOp.signature[0:20]
      hexZeroPad("0x00", 6), // uint48 validUntil - userOp.signature[20:26]
      hexZeroPad("0x00", 6), // uint48 validAfter - userOp.signature[26:32]
      await owner._signTypedData( // bytes memory signature - userOp.signature[32:97]
        {
          name: "Kernel",
          version: "0.0.1",
          chainId: await provider.getNetwork().then(x => x.chainId),
          verifyingContract: account.address
        },
        {
          ValidateUserOpPlugin: [
            { name: "plugin", type: "address" },
            { name: "validUntil", type: "uint48" },
            { name: "validAfter", type: "uint48" },
            { name: "data", type: "bytes" }
          ]
        },
        {
          plugin: whitelistPlugin.address,
          validUntil: 0,
          validAfter: 0,
          data: whitelistWallet.address
        }
      )
    ])

    const whitelistSig = await whitelistWallet._signTypedData(
      {
        name: "WhitelistPlugin",
        version: "0.0.1",
        chainId: await provider.getNetwork().then(x => x.chainId),
        verifyingContract: account.address
      },
      {
        Session: [
          { name: "userOpHash", type: "bytes32" },
          { name: "nonce", type: "uint256" }
        ]
      },
      {
        userOpHash: await entryPoint.getUserOpHash(userOp),
        nonce: await account["getNonce()"]()
      }
    )

    userOp.signature = hexConcat([ownerSig, defaultAbiCoder.encode( // userOp.signature[97:]
      ["bytes", "bytes"],
      [whitelistWallet.address, whitelistSig])
    ])

    await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    expect(await randomWallet.getBalance()).to.eq(parseEther("0.1"))
  }

  async function subscription() {
    const { provider, owner, bundler, randomWallet, entryPoint, factory, createEmptyUserOp, estimateUserOpGas } = await loadFixture(deployFixture)
    const subscriptionProvider = ethers.Wallet.createRandom().connect(provider)

    await factory.createAccount(owner.address, 0)
    const accountAddr = await factory.getAccountAddress(owner.address, 0)
    const account = await ethers.getContractAt("Kernel", accountAddr)
    owner.sendTransaction({ to: account.address, value: parseEther("1") })
    const userOp = await createEmptyUserOp(accountAddr, "Kernel")
    userOp.callData = (await ethers.getContractFactory("Kernel")).interface.encodeFunctionData(
      "executeAndRevert",
      [randomWallet.address, parseEther("0.1"), "0x", 0]
    )
    await estimateUserOpGas(userOp)

    const payment = hexZeroPad(hexValue(parseEther("0.1")), 32)
    const period = hexZeroPad(hexValue(2592000), 32) // 30 days
    const merkle = new MerkleTree(
      [payment, period], keccak256, { sortPairs: true, hashLeaves: true }
      // [payment], keccak256, { sortPairs: true, hashLeaves: true }
    )
    const merkleRoot = "0x" + merkle.getRoot().toString("hex")

    const subscriptionPlugin = await (await ethers.getContractFactory("SubscriptionPlugin")).deploy()

    const ownerSig = await owner._signTypedData(
      {
        name: "Kernel",
        version: "0.0.1",
        chainId: await provider.getNetwork().then(x => x.chainId),
        verifyingContract: account.address
      },
      {
        ValidateUserOpPlugin: [
          { name: "plugin", type: "address" },
          { name: "validUntil", type: "uint48" },
          { name: "validAfter", type: "uint48" },
          { name: "data", type: "bytes" }
        ]
      },
      {
        plugin: subscriptionPlugin.address,
        validUntil: 0,
        validAfter: 0,
        data: hexConcat([subscriptionProvider.address, merkleRoot])
      }
    )
    
    const subscriptionProviderSig = await subscriptionProvider._signTypedData(
      {
        name: "SubscriptionPlugin",
        version: "0.0.1",
        chainId: await provider.getNetwork().then(x => x.chainId),
        verifyingContract: account.address
      },
      {
        Session: [
          { name: "userOpHash", type: "bytes32" },
          { name: "nonce", type: "uint256" }
        ]
      },
      {
        userOpHash: await entryPoint.getUserOpHash(userOp),
        nonce: await account["getNonce()"]()
      }
    )

    // packedOwnerSig is same for each payment
    const packedOwnerSig = hexConcat([
      subscriptionPlugin.address, // address plugin - userOp.signature[0:20]
      hexZeroPad("0x00", 6), // uint48 validUntil - userOp.signature[20:26]
      hexZeroPad("0x00", 6), // uint48 validAfter - userOp.signature[26:32]
      ownerSig // bytes memory signature - userOp.signature[32:97]
    ])
    
    userOp.signature = hexConcat([
      packedOwnerSig,
      defaultAbiCoder.encode( // userOp.signature[97:]
        ["bytes", "bytes"],
        [
          hexConcat([ // data
            subscriptionProvider.address, // address sessionKey = address(bytes20(data[0:20]))
            merkleRoot // bytes32 merkleRoot = bytes32(data[20:52])
          ]),
          hexConcat([ // signature
            payment, // bytes32 leaf1 = keccak256(signature[0:32])
            period, // bytes32 leaf2 = keccak256(signature[32:64])
            subscriptionProviderSig, // signature = signature[64:129]
            // (bytes32[] memory proof1, bytes32[] memory proof2) = abi.decode(signature[129:], (bytes32[], bytes32[]))
            defaultAbiCoder.encode(["bytes32[]", "bytes32[]"], [merkle.getHexProof(keccak256(payment)), merkle.getHexProof(keccak256(period))])
          ])
        ]
      )
    ])

    await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    expect(await randomWallet.getBalance()).to.eq(parseEther("0.1"))
  }

  // it("Should create account", createAccount)
  // it("Should work with session key", sessionKey)
  // it("Should work with whitelist", whitelist)
  it("Should work with subscription", subscription)

})
