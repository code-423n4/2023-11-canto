# Winning bot race submission
  This is the top-ranked automated findings report, from IllIllI-bot bot. All findings in this report will be considered known issues for the purposes of your C4 audit.

  ## Summary 
| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[M&#x2011;01](#01)] | The `owner` is a single point of failure and a centralization risk | 5| 0|
| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[L&#x2011;01](#01)] | `safeApprove()` is deprecated | 1| 0|
| [[L&#x2011;02](#02)] | Code does not follow the best practice of check-effects-interaction | 10| 0|
| [[L&#x2011;03](#03)] | Consider implementing two-step procedure for updating protocol addresses | 2| 0|
| [[L&#x2011;04](#04)] | Local variable shadows state variable | 4| 0|
| [[L&#x2011;05](#05)] | Loss of precision | 1| 0|
| [[L&#x2011;06](#06)] | Missing checks for `address(0x0)` in the constructor | 3| 0|
| [[L&#x2011;07](#07)] | Missing checks for `address(0x0)` when updating `address` state variables | 1| 0|
| [[L&#x2011;08](#08)] | Use of `tx.origin` is unsafe in almost every context | 2| 0|
| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[G&#x2011;01](#01)] | Assembly: Use scratch space for building calldata | 7| 1540|
| [[G&#x2011;02](#02)] | `++i`/`i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow, as is the case when used in `for`- and `while`-loops | 1| 60|
| [[G&#x2011;03](#03)] | Assembly: Check `msg.sender` using `xor` and the scratch space | 3| 0|
| [[G&#x2011;04](#04)] | Consider using solady's `FixedPointMathLib` | 7| 0|
| [[G&#x2011;05](#05)] | Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes | 3| 25650|
| [[G&#x2011;06](#06)] | State variables only set in the constructor should be declared `immutable` | 1| 2097|
| [[G&#x2011;07](#07)] | Using `calldata` instead of `memory` for read-only arguments in `public`/`external` functions saves gas | 3| 360|
| [[G&#x2011;08](#08)] | Avoid transferring amounts of zero in order to save gas | 9| 900|
| [[G&#x2011;09](#09)] | Avoid contract existence checks by using low-level calls | 7| 700|
| [[G&#x2011;10](#10)] | Using `bool`s for storage incurs overhead | 4| 400|
| [[G&#x2011;11](#11)] | Multiple accesses of a mapping/array should use a local variable cache | 19| 798|
| [[G&#x2011;12](#12)] | Optimize names to save gas | 1| 22|
| [[G&#x2011;13](#13)] | Functions guaranteed to revert when called by normal users can be marked `payable` | 6| 126|
| [[G&#x2011;14](#14)] | Constructors can be marked `payable` | 4| 84|
| [[G&#x2011;15](#15)] | `unchecked {}`  can be used on the division of two `uint`s in order to save gas | 1| 20|
| [[G&#x2011;16](#16)] | Assembly: Use scratch space when building emitted events with two data arguments | 2| 30|
| [[G&#x2011;17](#17)] | `x += y` costs more gas than `x = x + y` for basic-typed state variables | 1| 10|
| [[G&#x2011;18](#18)] | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 1| 5|
| [[G&#x2011;19](#19)] | `>=` costs less gas than `>` | 5| 15|
| [[G&#x2011;20](#20)] | Inline `modifier`s that are only used once, to save gas | 1| 0|
| [[G&#x2011;21](#21)] | Reduce deployment costs by tweaking contracts' metadata | 4| 0|
| [[G&#x2011;22](#22)] | Reduce gas usage by moving to Solidity 0.8.19 or later | 2| 0|
| [[G&#x2011;23](#23)] | Remove or replace unused state variables | 1| 0|
| [[G&#x2011;24](#24)] | Use custom errors rather than `revert()`/`require()` strings to save gas | 12| 0|
| [[G&#x2011;25](#25)] | Using `private` rather than `public`, saves gas | 18| 0|
| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[N&#x2011;01](#01)] | `address`es shouldn't be hard-coded | 3| 0|
| [[N&#x2011;02](#02)] | `constant`s should be defined rather than using magic numbers | 14| 0|
| [[N&#x2011;03](#03)] | `if`-statement can be converted to a ternary | 1| 0|
| [[N&#x2011;04](#04)] | Assembly blocks should have extensive comments | 1| 0|
| [[N&#x2011;05](#05)] | Avoid the use of sensitive terms | 32| 0|
| [[N&#x2011;06](#06)] | Consider adding a block/deny-list | 2| 0|
| [[N&#x2011;07](#07)] | Consider adding emergency-stop functionality | 3| 0|
| [[N&#x2011;08](#08)] | Consider adding formal verification proofs | 1| 0|
| [[N&#x2011;09](#09)] | Consider defining system-wide constants in a single file | 3| 0|
| [[N&#x2011;10](#10)] | Consider disabling `renounceOwnership()` | 3| 0|
| [[N&#x2011;11](#11)] | Consider making contracts `Upgradeable` | 4| 0|
| [[N&#x2011;12](#12)] | Consider moving `msg.sender` checks to a common authorization `modifier` | 2| 0|
| [[N&#x2011;13](#13)] | Consider using `delete` rather than assigning zero/false to clear values | 1| 0|
| [[N&#x2011;14](#14)] | Consider using a `struct` rather than having many function input parameters | 1| 0|
| [[N&#x2011;15](#15)] | Consider using named mappings | 10| 0|
| [[N&#x2011;16](#16)] | Constants in comparisons should appear on the left side | 11| 0|
| [[N&#x2011;17](#17)] | Contract should expose an `interface` | 18| 0|
| [[N&#x2011;18](#18)] | Contracts should have full test coverage | 1| 0|
| [[N&#x2011;19](#19)] | Custom errors should be used rather than `revert()`/`require()` | 12| 0|
| [[N&#x2011;20](#20)] | Duplicated `require()`/`revert()` checks should be refactored to a modifier or function | 1| 0|
| [[N&#x2011;21](#21)] | Event is not properly `indexed` | 1| 0|
| [[N&#x2011;22](#22)] | Events are missing sender information | 3| 0|
| [[N&#x2011;23](#23)] | Events may be emitted out of order due to reentrancy | 8| 0|
| [[N&#x2011;24](#24)] | Large multiples of ten should use scientific notation | 4| 0|
| [[N&#x2011;25](#25)] | Large numeric literals should use underscores for readability | 6| 0|
| [[N&#x2011;26](#26)] | Large or complicated code bases should implement invariant tests | 1| 0|
| [[N&#x2011;27](#27)] | Memory-safe annotation preferred over comment variant | 1| 0|
| [[N&#x2011;28](#28)] | Missing checks constructor/initializer assignments | 1| 0|
| [[N&#x2011;29](#29)] | Missing event and or timelock for critical parameter change | 1| 0|
| [[N&#x2011;30](#30)] | NatSpec: Contract declarations should have `@author` tags | 4| 0|
| [[N&#x2011;31](#31)] | NatSpec: Contract declarations should have `@dev` tags | 4| 0|
| [[N&#x2011;32](#32)] | NatSpec: Contract declarations should have `@notice` tags | 4| 0|
| [[N&#x2011;33](#33)] | NatSpec: Contract declarations should have `@title` tags | 4| 0|
| [[N&#x2011;34](#34)] | NatSpec: Contract declarations should have descriptions | 4| 0|
| [[N&#x2011;35](#35)] | NatSpec: Event `@param` tag is missing | 38| 0|
| [[N&#x2011;36](#36)] | NatSpec: Event declarations should have descriptions | 12| 0|
| [[N&#x2011;37](#37)] | NatSpec: Function `@param` tag is missing | 11| 0|
| [[N&#x2011;38](#38)] | NatSpec: Function `@return` tag is missing | 12| 0|
| [[N&#x2011;39](#39)] | NatSpec: Function declarations should have `@notice` tags | 4| 0|
| [[N&#x2011;40](#40)] | NatSpec: Function declarations should have descriptions | 4| 0|
| [[N&#x2011;41](#41)] | NatSpec: Modifier declarations should have `@notice` tags | 1| 0|
| [[N&#x2011;42](#42)] | NatSpec: Modifier declarations should have descriptions | 1| 0|
| [[N&#x2011;43](#43)] | NatSpec: Public state variable declarations should have descriptions | 6| 0|
| [[N&#x2011;44](#44)] | NatSpec: Use `@inheritdoc` to inherit the NatSpec of the base function | 2| 0|
| [[N&#x2011;45](#45)] | Non-library/interface files should use fixed compiler versions, not floating ones | 2| 0|
| [[N&#x2011;46](#46)] | Ownable contract never uses `onlyOwner` modifier | 1| 0|
| [[N&#x2011;47](#47)] | Style guide: Contract names should use CamelCase | 2| 0|
| [[N&#x2011;48](#48)] | Style guide: Function ordering does not follow the Solidity style guide | 3| 0|
| [[N&#x2011;49](#49)] | Style guide: Lines are too long | 11| 0|
| [[N&#x2011;50](#50)] | Style guide: Non-`external`/`public` function names should begin with an underscore | 1| 0|
| [[N&#x2011;51](#51)] | Style guide: Variable names for `immutable`s should use CONSTANT_CASE | 2| 0|
| [[N&#x2011;52](#52)] | Unused `public` contract variable | 1| 0|
| [[N&#x2011;53](#53)] | Unused import | 1| 0|
| [[N&#x2011;54](#54)] | Use of `override` is unnecessary | 2| 0|
| [[N&#x2011;55](#55)] | Use the latest solidity (prior to 0.8.20 if on L2s) for deployment | 2| 0|
| [[N&#x2011;56](#56)] | Using `>`/`>=` without specifying an upper bound is unsafe | 2| 0|
| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[D&#x2011;01](#01)] | ~~`approve()`/`safeApprove()` may revert if the current approval is not zero~~ | 1| 0|
| [[D&#x2011;02](#02)] | ~~Avoid updating storage when the value hasn't changed~~ | 2| 0|
| [[D&#x2011;03](#03)] | ~~Avoid Zero to Non-Zero Storage Writes Where Possible~~ | 2| 0|
| [[D&#x2011;04](#04)] | ~~Bad bot rules~~ | 2| 0|
| [[D&#x2011;05](#05)] | ~~Consider adding a block/deny-list~~ | 2| 0|
| [[D&#x2011;06](#06)] | ~~Constant decimal values~~ | 3| 0|
| [[D&#x2011;07](#07)] | ~~Constant redefined elsewhere~~ | 1| 0|
| [[D&#x2011;08](#08)] | ~~Contracts do not work with fee-on-transfer tokens~~ | 1| 0|
| [[D&#x2011;09](#09)] | ~~Control structures do not follow the Solidity Style Guide~~ | 2| 0|
| [[D&#x2011;10](#10)] | ~~Default `bool` values are manually reset~~ | 1| 0|
| [[D&#x2011;11](#11)] | ~~Duplicated `require()`/`revert()` checks should be refactored to a modifier or function~~ | 10| 0|
| [[D&#x2011;12](#12)] | ~~Duplicated require()/revert() checks should be refactored to a modifier Or function to save gas~~ | 1| 0|
| [[D&#x2011;13](#13)] | ~~Enable IR-based code generation~~ | 1| 0|
| [[D&#x2011;14](#14)] | ~~Event names should use CamelCase~~ | 12| 0|
| [[D&#x2011;15](#15)] | ~~Events that mark critical parameter changes should contain both the old and the new value~~ | 11| 0|
| [[D&#x2011;16](#16)] | ~~Inconsistent comment spacing~~ | 4| 0|
| [[D&#x2011;17](#17)] | ~~It is standard for all external and public functions to be override from an interface~~ | 2| 0|
| [[D&#x2011;18](#18)] | ~~It's not standard to end and begin a code object on the same line~~ | 11| 0|
| [[D&#x2011;19](#19)] | ~~Large approvals may not work with some ERC20 tokens~~ | 1| 0|
| [[D&#x2011;20](#20)] | ~~Loss of precision~~ | 1| 0|
| [[D&#x2011;21](#21)] | ~~Low level calls with Solidity before 0.8.14 result in an optimiser bug~~ | 1| 0|
| [[D&#x2011;22](#22)] | ~~Missing checks for state variable assignments~~ | 5| 0|
| [[D&#x2011;23](#23)] | ~~Missing event and or timelock for critical parameter change~~ | 6| 0|
| [[D&#x2011;24](#24)] | ~~Must approve or increase allowance first~~ | 4| 0|
| [[D&#x2011;25](#25)] | ~~NatSpec: Function declarations should have `@notice` tags~~ | 20| 0|
| [[D&#x2011;26](#26)] | ~~Not using the named return variables anywhere in the function is confusing~~ | 1| 0|
| [[D&#x2011;27](#27)] | ~~Re-org attack~~ | 1| 0|
| [[D&#x2011;28](#28)] | ~~Reduce gas usage by moving to Solidity 0.8.19 or later~~ | 2| 0|
| [[D&#x2011;29](#29)] | ~~Return values of transfer()/transferFrom() not checked~~ | 1| 0|
| [[D&#x2011;30](#30)] | ~~Revert on transfer to the zero address~~ | 13| 0|
| [[D&#x2011;31](#31)] | ~~safeMint should be used in place of mint~~ | 1| 0|
| [[D&#x2011;32](#32)] | ~~Setters should prevent re-setting of the same value~~ | 2| 0|
| [[D&#x2011;33](#33)] | ~~Solidity version 0.8.20 may not work on other chains due to `PUSH0`~~ | 2| 0|
| [[D&#x2011;34](#34)] | ~~SPDX identifier should be the in the first line of a solidity file~~ | 4| 0|
| [[D&#x2011;35](#35)] | ~~State variable read in a loop~~ | 1| 0|
| [[D&#x2011;36](#36)] | ~~Storage Write Removal Bug On Conditional Early Termination~~ | 1| 0|
| [[D&#x2011;37](#37)] | ~~Style guide: Contract does not follow the Solidity style guide's suggested layout ordering~~ | 4| 0|
| [[D&#x2011;38](#38)] | ~~Style guide: Function Names Not in mixedCase~~ | 2| 0|
| [[D&#x2011;39](#39)] | ~~Style guide: Function names should use lowerCamelCase~~ | 1| 0|
| [[D&#x2011;40](#40)] | ~~Tokens may be minted to `address(0x0)`~~ | 1| 0|
| [[D&#x2011;41](#41)] | ~~Top level pragma declarations should be separated by two blank lines~~ | 4| 0|
| [[D&#x2011;42](#42)] | ~~Top-level declarations should be separated by at least two lines~~ | 4| 0|
| [[D&#x2011;43](#43)] | ~~Trade-offs Between Modifiers and Internal Functions~~ | 1| 0|
| [[D&#x2011;44](#44)] | ~~Unnecessary look up in if condition~~ | 5| 0|
| [[D&#x2011;45](#45)] | ~~Unused function parameter~~ | 1| 0|
| [[D&#x2011;46](#46)] | ~~Unused import~~ | 18| 0|
| [[D&#x2011;47](#47)] | ~~Unusual loop variable~~ | 1| 0|
| [[D&#x2011;48](#48)] | ~~Use != 0 instead of > 0 for unsigned integer comparison~~ | 4| 0|
| [[D&#x2011;49](#49)] | ~~Use `_safeMint` instead of `_mint` for ERC721~~ | 3| 0|
| [[D&#x2011;50](#50)] | ~~Use `assembly` to write address/contract type storage values~~ | 5| 0|
| [[D&#x2011;51](#51)] | ~~Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes~~ | 1| 0|
| [[D&#x2011;52](#52)] | ~~Use assembly to emit events, in order to save gas~~ | 10| 0|
| [[D&#x2011;53](#53)] | ~~Use delete instead of setting mapping/state variable to zero, to save gas~~ | 2| 0|
| [[D&#x2011;54](#54)] | ~~Use of a single-step ownership transfer~~ | 1| 0|
| [[D&#x2011;55](#55)] | ~~Using `calldata` instead of `memory` for read-only arguments in `public`/`external` functions saves gas~~ | 1| 0|
| [[D&#x2011;56](#56)] | ~~Using bitmap to store bool states can save gas~~ | 3| 0|
 **Note:** There is a section for disputed findings below the usual findings sections ### Medium Risk Issues <a name="01"></a>


### [M&#x2011;01] The `owner` is a single point of failure and a centralization risk
Having a single EOA as the only owner of contracts is a large centralization risk and a single point of failure. A single private key may be taken in a hack, or the sole holder of the key may become unable to retrieve the key when necessary, or the single owner can become malicious and perform a rug-pull. Consider changing to a multi-signature setup, and or having a role-based authorization model.

*There are 5 instance(s) of this issue:*

```solidity
File: src/Market.sol

104:     function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {

244:     function claimPlatformFee() external onlyOwner {

300:     function restrictShareCreation(bool _isRestricted) external onlyOwner {

309:     function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

```


*GitHub* : [104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104-L104),[244](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L244-L244),[300](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L300-L300),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309-L309)

```solidity
File: src/asD.sol

72:      function withdrawCarry(uint256 _amount) external onlyOwner {

```


*GitHub* : [72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L72-L72)### Low Risk Issues <a name="01"></a>


### [L&#x2011;01] `safeApprove()` is deprecated
[Deprecated](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/bfff03c0d2a59bcd8e2ead1da9aed9edf0080d05/contracts/token/ERC20/utils/SafeERC20.sol#L38-L45) in favor of `safeIncreaseAllowance()` and `safeDecreaseAllowance()`. If only setting the initial allowance to the value that means infinite, `safeIncreaseAllowance()` can be used instead. The function may currently work, but if a bug is found in this version of OpenZeppelin, and the version that you're forced to upgrade to no longer has this function, you'll encounter unnecessary delays in porting and testing replacement contracts.

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

51:           SafeERC20.safeApprove(note, cNote, _amount);

```


*GitHub* : [51](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L51)
### [L&#x2011;02] Code does not follow the best practice of check-effects-interaction
Code should follow the best-practice of [check-effects-interaction](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-11-coding-patterns/topic/checks-effects-interactions/), where state variables are updated before any external calls are made. Doing so prevents a large class of reentrancy bugs.

*There are 10 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit safeTransferFrom() called prior to this assignment
159:         rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit safeTransferFrom() called prior to this assignment
161:         shareData[_id].tokenCount += _amount;

/// @audit safeTransferFrom() called prior to this assignment
162:         shareData[_id].tokensInCirculation += _amount;

/// @audit safeTransferFrom() called prior to this assignment
163:         tokensByAddress[_id][msg.sender] += _amount;

/// @audit safeTransferFrom() called prior to this assignment
210:         rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit safeTransferFrom() called prior to this assignment
211:         tokensByAddress[_id][msg.sender] -= _amount;

/// @audit safeTransferFrom() called prior to this assignment
212:         shareData[_id].tokensInCirculation -= _amount;

/// @audit safeTransferFrom() called prior to this assignment
233:         rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit safeTransferFrom() called prior to this assignment
234:         tokensByAddress[_id][msg.sender] += _amount;

/// @audit safeTransferFrom() called prior to this assignment
235:         shareData[_id].tokensInCirculation += _amount;

```


*GitHub* : [159](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L159-L159),[161](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L161-L161),[162](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L162-L162),[163](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L163-L163),[210](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L210-L210),[211](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L211-L211),[212](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L212-L212),[233](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L233-L233),[234](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L234-L234),[235](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L235-L235)
### [L&#x2011;03] Consider implementing two-step procedure for updating protocol addresses
A copy-paste error or a typo may end up bricking protocol functionality, or sending tokens to an address with no known private key. Consider implementing a two-step procedure for updating protocol addresses, where the recipient is set as pending, and must 'accept' the assignment by making an affirmative call. A straight forward way of doing this would be to have the target contracts implement [EIP-165](https://eips.ethereum.org/EIPS/eip-165), and to have the 'set' functions ensure that the recipient is of the right interface type.

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

104      function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {
105          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");
106          whitelistedBondingCurves[_bondingCurve] = _newState;
107          emit BondingCurveStateChange(_bondingCurve, _newState);
108:     }

309      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {
310          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");
311          whitelistedShareCreators[_address] = _isWhitelisted;
312:     }

```


*GitHub* : [104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104-L108),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309-L312)
### [L&#x2011;04] Local variable shadows state variable

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit _uri is an existing state variable
91:      constructor(string memory _uri, address _paymentToken) ERC1155(_uri) Ownable() {

```


*GitHub* : [91](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L91-L91)

```solidity
File: src/asD.sol

/// @audit _name is an existing state variable
29:          string memory _name,

/// @audit _symbol is an existing state variable
30:          string memory _symbol,

/// @audit _owner is an existing state variable
31:          address _owner,

```


*GitHub* : [29](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L29-L29),[30](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L30-L30),[31](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L31-L31)
### [L&#x2011;05] Loss of precision
Division by large numbers may result in the result being zero, due to solidity not supporting fractions. Consider requiring a minimum amount for the numerator to ensure that it is always larger than the denominator

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit division by _tokenCount
290:             shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;

```


*GitHub* : [290](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L290-L290)
### [L&#x2011;06] Missing checks for `address(0x0)` in the constructor

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit _paymentToken
92:          token = IERC20(_paymentToken);

```


*GitHub* : [92](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L92-L92)

```solidity
File: src/asD.sol

/// @audit _cNote
36:          cNote = _cNote;

```


*GitHub* : [36](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L36-L36)

```solidity
File: src/asDFactory.sol

/// @audit _cNote
25:          cNote = _cNote;

```


*GitHub* : [25](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L25-L25)
### [L&#x2011;07] Missing checks for `address(0x0)` when updating `address` state variables

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit _bondingCurve
123:         shareData[id].bondingCurve = _bondingCurve;

```


*GitHub* : [123](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L123-L123)
### [L&#x2011;08] Use of `tx.origin` is unsafe in almost every context
According to [Vitalik Buterin](https://ethereum.stackexchange.com/questions/196/how-do-i-make-my-dapp-serenity-proof), contracts should _not_ `assume that tx.origin will continue to be usable or meaningful`. An example of this is [EIP-3074](https://eips.ethereum.org/EIPS/eip-3074#allowing-txorigin-as-signer-1) which explicitly mentions the intention to change its semantics when it's used with new op codes. There have also been calls to [remove](https://github.com/ethereum/solidity/issues/683) `tx.origin`, and there are [security issues](solidity.readthedocs.io/en/v0.4.24/security-considerations.html#tx-origin) associated with using it for authorization. For these reasons, it's best to completely avoid the feature.

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

95               Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);
96:              turnstile.register(tx.origin);

```


*GitHub* : [95](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L95-L96)

```solidity
File: src/asDFactory.sol

28               Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);
29:              turnstile.register(tx.origin);

```


*GitHub* : [28](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L28-L29)### Gas Risk Issues <a name="01"></a>


### [G&#x2011;01] Assembly: Use scratch space for building calldata
If an external call's calldata can fit into two or fewer words, use the scratch space to build the calldata, rather than allowing Solidity to do a memory expansion.

*There are 7 instance(s) of this issue:*

```solidity
File: src/Market.sol

96:              turnstile.register(tx.origin);

```


*GitHub* : [96](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L96-L96)

```solidity
File: src/asD.sol

40:              turnstile.register(_csrRecipient);

52:          uint256 returnCode = cNoteToken.mint(_amount);

63:          uint256 returnCode = cNoteToken.redeemUnderlying(_amount); // Request _amount of NOTE (the underlying of cNOTE)

75:          uint256 maximumWithdrawable = (CTokenInterface(cNote).balanceOf(address(this)) * exchangeRate) /

85:          uint256 returnCode = CErc20Interface(cNote).redeemUnderlying(_amount);

```


*GitHub* : [40](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L40-L40),[52](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L52-L52),[63](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L63-L63),[75](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L75-L75),[85](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L85-L85)

```solidity
File: src/asDFactory.sol

29:              turnstile.register(tx.origin);

```


*GitHub* : [29](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L29-L29)
### [G&#x2011;02] `++i`/`i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow, as is the case when used in `for`- and `while`-loops
The `unchecked` keyword is new in solidity version 0.8.0, so this only applies to that version or higher, which these instances are. This saves **30-40 gas [per loop](https://gist.github.com/hrkrshnn/ee8fabd532058307229d65dcd5836ddc#the-increment-in-for-loop-post-condition-can-be-made-unchecked)**

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

20:           for (uint256 i = shareCount; i < shareCount + amount; i++) {

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L20)
### [G&#x2011;03] Assembly: Check `msg.sender` using `xor` and the scratch space
See [this](https://code4rena.com/reports/2023-05-juicebox#g-06-use-assembly-to-validate-msgsender) prior finding for details on the conversion

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

81           require(
82               !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83               "Not allowed"
84:          );

151:         require(shareData[_id].creator != msg.sender, "Creator cannot buy");

254:         require(shareData[_id].creator == msg.sender, "Not creator");

```


*GitHub* : [81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L81-L84),[151](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L151-L151),[254](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L254-L254)
### [G&#x2011;04] Consider using solady's `FixedPointMathLib`
Saves gas, and works to avoid unnecessary [overflows](https://github.com/Vectorized/solady/blob/6cce088e69d6e46671f2f622318102bd5db77a65/src/utils/FixedPointMathLib.sol#L267).

*There are 7 instance(s) of this issue:*

```solidity
File: src/Market.sol

197:         fee = (priceForOne * _amount * NFT_FEE_BPS) / 10_000;

275              ((shareData[_id].shareHolderRewardsPerTokenScaled - lastClaimedValue) * tokensByAddress[_id][msg.sender]) /
276:             1e18;

285:         uint256 shareHolderFee = (_fee * HOLDER_CUT_BPS) / 10_000;

286:         uint256 shareCreatorFee = (_fee * CREATOR_CUT_BPS) / 10_000;

290:             shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;

```


*GitHub* : [197](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L197-L197),[275](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L275-L276),[285](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L285-L285),[286](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L286-L286),[290](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L290-L290)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

23:              fee += (getFee(i) * tokenPrice) / 1e18;

```


*GitHub* : [23](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L23-L23)

```solidity
File: src/asD.sol

75           uint256 maximumWithdrawable = (CTokenInterface(cNote).balanceOf(address(this)) * exchangeRate) /
76:              1e28 -

```


*GitHub* : [75](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L75-L76)
### [G&#x2011;05] Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes
Avoids a Gsset (**20000 gas**) when changing from `false` to `true`, after having been `true` in the past. Since most of the bools aren't changed twice in one transaction, I've counted the amount of gas as half of the full amount, for each variable. Note that public state variables can be re-written to be `private` and use `uint256`, but have public getters returning `bool`s.

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit reset in: changeBondingCurveAllowed()
49:      mapping(address => bool) public whitelistedBondingCurves;

/// @audit reset in: restrictShareCreation()
61:      bool public shareCreationRestricted = true;

/// @audit reset in: changeShareCreatorWhitelist()
64:      mapping(address => bool) public whitelistedShareCreators;

```


*GitHub* : [49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49-L49),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L61),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L64)
### [G&#x2011;06] State variables only set in the constructor should be declared `immutable`
Avoids a Gsset (**20000 gas**) in the constructor, and replaces the first access in each transaction (Gcoldsload - **2100 gas**) and each access thereafter (Gwarmacces - **100 gas**) with a `PUSH32` (**3 gas**). 

While `string`s are not value types, and therefore cannot be `immutable`/`constant` if not hard-coded outside of the constructor, the same behavior can be achieved by making the current contract `abstract` with `virtual` functions for the `string` accessors, and having a child contract override the functions with the hard-coded implementation-specific values.

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

27:      uint256 public shareCount;

```


*GitHub* : [27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L27-L27)
### [G&#x2011;07] Using `calldata` instead of `memory` for read-only arguments in `public`/`external` functions saves gas
When a function with a `memory` array is called externally, the `abi.decode()` step has to copy read each index of the `calldata` to `memory`. **Each copy costs at least 60 gas** (i.e. `60 * <mem_array>.length`). Using `calldata` directly, obviates the need for copies of words of the struct/array not being read. Note that even if an interface defines a function as having `memory` arguments, it's still valid for implementation contracts to use `calldata` arguments instead. 

If the array is passed to an `internal` function which passes the array to another internal function where the array is modified and therefore `memory` is used in the `external` call, it's still more gass-efficient to use `calldata` when the `external` function uses modifiers, since the modifiers may prevent the internal functions from being called. Structs have the same overhead as an array of length one

Note that I've also flagged instances where the function is `public` but can be marked as `external` since it's not called by the contract (you may have to change the visibility of the `interface`'s version of the function to `external` [first](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding)), and cases where a constructor is involved

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit createNewShare(_metadataURI)
117:         string memory _metadataURI

```


*GitHub* : [117](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L117-L117)

```solidity
File: src/asDFactory.sol

/// @audit create(_name)
/// @audit create(_symbol)
33:      function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33),[33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33)
### [G&#x2011;08] Avoid transferring amounts of zero in order to save gas
Skipping the external call when nothing will be transferred, will save at least **100 gas**

*There are 9 instance(s) of this issue:*

```solidity
File: src/Market.sol

153:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), price + fee);

187:         SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim + price - fee);

206:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);

229:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);

238:         SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);

247:         SafeERC20.safeTransfer(token, msg.sender, amount);

257:         SafeERC20.safeTransfer(token, msg.sender, amount);

```


*GitHub* : [153](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L153-L153),[187](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L187-L187),[206](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L206-L206),[229](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L229-L229),[238](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L238-L238),[247](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L247-L247),[257](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L257-L257)

```solidity
File: src/asD.sol

50:          SafeERC20.safeTransferFrom(note, msg.sender, address(this), _amount);

66:          SafeERC20.safeTransfer(note, msg.sender, _amount);

```


*GitHub* : [50](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L50-L50),[66](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L66-L66)
### [G&#x2011;09] Avoid contract existence checks by using low-level calls
Prior to 0.8.10 the compiler inserted extra code, including `EXTCODESIZE` (**100 gas**), to check for contract existence for external function calls. In more recent solidity versions, the compiler will not insert these checks if the external call has a return value. Similar behavior can be achieved in earlier versions by using low-level calls, since low-level calls never check for contract existence. Note that it [still](https://gist.github.com/IllIllI000/fbd5861a8e587cb1c1aab55a106bb9a7) saves gas, even if the return value is not directly used.

*There are 7 instance(s) of this issue:*

```solidity
File: src/asD.sol

40:              turnstile.register(_csrRecipient);

52:          uint256 returnCode = cNoteToken.mint(_amount);

63:          uint256 returnCode = cNoteToken.redeemUnderlying(_amount); // Request _amount of NOTE (the underlying of cNOTE)

73:          uint256 exchangeRate = CTokenInterface(cNote).exchangeRateCurrent(); // Scaled by 1 * 10^(18 - 8 + Underlying Token Decimals), i.e. 10^(28) in our case

75:          uint256 maximumWithdrawable = (CTokenInterface(cNote).balanceOf(address(this)) * exchangeRate) /

85:          uint256 returnCode = CErc20Interface(cNote).redeemUnderlying(_amount);

```


*GitHub* : [40](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L40-L40),[52](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L52-L52),[63](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L63-L63),[73](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L73-L73),[75](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L75-L75),[85](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L85-L85)

```solidity
File: src/asDFactory.sol

29:              turnstile.register(tx.origin);

```


*GitHub* : [29](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L29-L29)
### [G&#x2011;10] Using `bool`s for storage incurs overhead
```solidity
// Booleans are more expensive than uint256 or any type that takes up a full
// word because each write operation emits an extra SLOAD to first read the
// slot's contents, replace the bits taken up by the boolean, and then write
// back. This is the compiler's defense against contract upgrades and
// pointer aliasing, and it cannot be disabled.
```
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27
Use `uint256(0)` and `uint256(1)` for true/false to avoid a Gwarmaccess (**[100 gas](https://gist.github.com/IllIllI000/1b70014db712f8572a72378321250058)**) for the extra SLOAD

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

49:      mapping(address => bool) public whitelistedBondingCurves;

61:      bool public shareCreationRestricted = true;

64:      mapping(address => bool) public whitelistedShareCreators;

```


*GitHub* : [49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49-L49),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L61),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L64)

```solidity
File: src/asDFactory.sol

15:      mapping(address => bool) public isAsD;

```


*GitHub* : [15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L15-L15)
### [G&#x2011;11] Multiple accesses of a mapping/array should use a local variable cache
The instances below point to the second+ access of a value inside a mapping/array, within a function. Caching a mapping's value in a local `storage` or `calldata` variable when the value is accessed [multiple times](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0), saves **~42 gas per access** due to not having to recalculate the key's keccak256 hash (Gkeccak256 - **30 gas**) and that calculation's associated stack operations. Caching an array's struct avoids recalculating the array offsets into memory/calldata

*There are 19 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit shareData[id] on line 123
124:          shareData[id].creator = msg.sender;

/// @audit shareData[id] on line 124
125:          shareData[id].metadataURI = _metadataURI;

/// @audit shareData[_id] on line 134
135:          (price, fee) = IBondingCurve(bondingCurve).getPriceAndFee(shareData[_id].tokenCount + 1, _amount);

/// @audit shareData[_id] on line 143
144:          (price, fee) = IBondingCurve(bondingCurve).getPriceAndFee(shareData[_id].tokenCount - _amount + 1, _amount);

/// @audit shareData[_id] on line 151
158:          _splitFees(_id, fee, shareData[_id].tokensInCirculation);

/// @audit shareData[_id] on line 158
159:          rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit shareData[_id] on line 159
161:          shareData[_id].tokenCount += _amount;

/// @audit shareData[_id] on line 161
162:          shareData[_id].tokensInCirculation += _amount;

/// @audit shareData[_id] on line 177
180:          rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit shareData[_id] on line 180
182:          shareData[_id].tokenCount -= _amount;

/// @audit shareData[_id] on line 182
183:          shareData[_id].tokensInCirculation -= _amount;

/// @audit shareData[_id] on line 195
196:          (uint256 priceForOne, ) = IBondingCurve(bondingCurve).getPriceAndFee(shareData[_id].tokenCount, 1);

/// @audit shareData[_id] on line 207
210:          rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit shareData[_id] on line 210
212:          shareData[_id].tokensInCirculation -= _amount;

/// @audit shareData[_id] on line 230
233:          rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;

/// @audit shareData[_id] on line 233
235:          shareData[_id].tokensInCirculation += _amount;

/// @audit shareData[_id] on line 254
255:          uint256 amount = shareData[_id].shareCreatorPool;

/// @audit shareData[_id] on line 255
256:          shareData[_id].shareCreatorPool = 0;

/// @audit shareData[_id] on line 288
290:              shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;

```


*GitHub* : [124](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L124),[125](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L125),[135](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L135),[144](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L144),[158](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L158),[159](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L159),[161](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L161),[162](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L162),[180](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L180),[182](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L182),[183](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L183),[196](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L196),[210](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L210),[212](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L212),[233](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L233),[235](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L235),[255](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L255),[256](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L256),[290](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L290)
### [G&#x2011;12] Optimize names to save gas
`public`/`external` function names and `public` member variable names can be optimized to save gas. See [this](https://gist.github.com/IllIllI000/a5d8b486a8259f9f77891a919febd1a9) link for an example of how it works. Below are the interfaces/abstract contracts that can be optimized so that the most frequently-called functions use the least amount of gas possible during method lookup. Method IDs that have two leading zero bytes can save **128 gas** each during deployment, and renaming functions to have lower method IDs will save **22 gas** per call, [per sorted position shifted](https://medium.com/joyso/solidity-how-does-function-name-affect-gas-consumption-in-smart-contract-47d270d8ac92)

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit changeBondingCurveAllowed(), createNewShare(), getBuyPrice(), getSellPrice(), buy(), sell(), getNFTMintingPrice(), mintNFT(), burnNFT(), claimPlatformFee(), claimCreatorFee(), claimHolderFee(), restrictShareCreation(), changeShareCreatorWhitelist()
10:   contract Market is ERC1155, Ownable2Step {

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10)
### [G&#x2011;13] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided. The extra opcodes avoided are 
`CALLVALUE`(2),`DUP1`(3),`ISZERO`(3),`PUSH2`(3),`JUMPI`(10),`PUSH1`(3),`DUP1`(3),`REVERT`(0),`JUMPDEST`(1),`POP`(2), which costs an average of about **21 gas per call** to the function, in addition to the extra deployment cost

*There are 6 instance(s) of this issue:*

```solidity
File: src/Market.sol

104:      function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {

114       function createNewShare(
115           string memory _shareName,
116           address _bondingCurve,
117           string memory _metadataURI
118:      ) external onlyShareCreator returns (uint256 id) {

244:      function claimPlatformFee() external onlyOwner {

300:      function restrictShareCreation(bool _isRestricted) external onlyOwner {

309:      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

```


*GitHub* : [104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104),[114](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L114-L118),[244](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L244),[300](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L300),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309)

```solidity
File: src/asD.sol

72:       function withdrawCarry(uint256 _amount) external onlyOwner {

```


*GitHub* : [72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L72)
### [G&#x2011;14] Constructors can be marked `payable`
Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided. A constructor can safely be marked as payable, since only the deployer would be able to pass funds, and the project itself would not pass any funds.

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

91:       constructor(string memory _uri, address _paymentToken) ERC1155(_uri) Ownable() {

```


*GitHub* : [91](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L91)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

10:       constructor(uint256 _priceIncrease) {

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L10)

```solidity
File: src/asD.sol

28        constructor(
29            string memory _name,
30            string memory _symbol,
31            address _owner,
32            address _cNote,
33            address _csrRecipient
34:       ) ERC20(_name, _symbol) {

```


*GitHub* : [28](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L28-L34)

```solidity
File: src/asDFactory.sol

24:       constructor(address _cNote) {

```


*GitHub* : [24](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L24)
### [G&#x2011;15] `unchecked {}`  can be used on the division of two `uint`s in order to save gas
The division cannot overflow, since both the numerator and the denominator are non-negative

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

290:             shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;

```


*GitHub* : [290](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L290-L290)
### [G&#x2011;16] Assembly: Use scratch space when building emitted events with two data arguments
Using the [scratch space](https://gist.github.com/IllIllI000/87c4f03139fa03780fa548b8e4b02b5b) for more than one, but at most two words worth of data (non-indexed arguments) will save gas over needing Solidity's abi memory expansion used for emitting normally.

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

220:         emit NFTsCreated(_id, msg.sender, _amount, fee);

240:         emit NFTsBurned(_id, msg.sender, _amount, fee);

```


*GitHub* : [220](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L220-L220),[240](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L240-L240)
### [G&#x2011;17] `x += y` costs more gas than `x = x + y` for basic-typed state variables
Using the addition operator instead of plus-equals saves **[10 gas](https://gist.github.com/IllIllI000/cbbfb267425b898e5be734d4008d4fe8)** because of extra `PUSH`es and `POP`s associated with the manipulation of the state variable when using `+=` for basic-typed state variables

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

295:         platformPool += platformFee;

```


*GitHub* : [295](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L295-L295)
### [G&#x2011;18] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)
Saves **5 gas per loop**

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

20:           for (uint256 i = shareCount; i < shareCount + amount; i++) {

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L20)
### [G&#x2011;19] `>=` costs less gas than `>`
The compiler uses opcodes `GT` and `ISZERO` for solidity code that uses `>`, but only requires `LT` for `>=`, [which saves **3 gas**](https://gist.github.com/IllIllI000/3dc79d25acccfa16dee4e83ffdc6ffde). If `<` is being used, the condition can be inverted.

*There are 5 instance(s) of this issue:*

```solidity
File: src/Market.sol

165          if (rewardsSinceLastClaim > 0) {
166              SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);
167:         }

216          if (rewardsSinceLastClaim > 0) {
217              SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);
218:         }

266          if (amount > 0) {
267              SafeERC20.safeTransfer(token, msg.sender, amount);
268:         }

289          if (_tokenCount > 0) {
290              shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;
291          } else {
292              // If there are no tokens in circulation, the fee goes to the platform
293              platformFee += shareHolderFee;
294:         }

```


*GitHub* : [165](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L165-L167),[216](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L216-L218),[266](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L266-L268),[289](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L289-L294)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

29           if (shareCount > 1) {
30               divisor = log2(shareCount);
31           } else {
32               divisor = 1;
33:          }

```


*GitHub* : [29](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L29-L33)
### [G&#x2011;20] Inline `modifier`s that are only used once, to save gas

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

80       modifier onlyShareCreator() {
81           require(
82               !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83               "Not allowed"
84           );
85           _;
86:      }

```


*GitHub* : [80](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L80-L86)
### [G&#x2011;21] Reduce deployment costs by tweaking contracts' metadata
See [this](https://www.rareskills.io/post/solidity-metadata) link, at its bottom, for full details

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [G&#x2011;22] Reduce gas usage by moving to Solidity 0.8.19 or later
See [this](https://blog.soliditylang.org/2023/02/22/solidity-0.8.19-release-announcement/#preventing-dead-code-in-runtime-bytecode) link for the full details. Additionally, every new release has new optimizations, which will save gas.

*There are 2 instance(s) of this issue:*

```solidity
File: src/asD.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L2-L2)

```solidity
File: src/asDFactory.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2-L2)
### [G&#x2011;23] Remove or replace unused state variables
Saves a storage slot. If the variable is assigned a non-zero value, saves Gsset (**20000 gas**). If it's assigned a zero value, saves Gsreset (**2900 gas**). If the variable remains unassigned, there is no gas savings unless the variable is `public`, in which case the compiler-generated non-payable getter deployment cost is saved. If the state variable is overriding an interface's public function, mark the variable as `constant` or `immutable` so that it does not use a storage slot

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

46:       mapping(uint256 => address) public shareBondingCurves;

```


*GitHub* : [46](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L46)
### [G&#x2011;24] Use custom errors rather than `revert()`/`require()` strings to save gas
Custom errors are available from solidity version 0.8.4. Custom errors save [**~50 gas**](https://gist.github.com/IllIllI000/ad1bd0d29a0101b25e57c293b4b0c746) each time they're hit by [avoiding having to allocate and store the revert string](https://blog.soliditylang.org/2021/04/21/custom-errors/#errors-in-depth). Not defining the strings also save deployment gas

*There are 12 instance(s) of this issue:*

```solidity
File: src/Market.sol

81            require(
82                !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83                "Not allowed"
84:           );

105:          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");

119:          require(whitelistedBondingCurves[_bondingCurve], "Bonding curve not whitelisted");

120:          require(shareIDs[_shareName] == 0, "Share already exists");

151:          require(shareData[_id].creator != msg.sender, "Creator cannot buy");

254:          require(shareData[_id].creator == msg.sender, "Not creator");

301:          require(shareCreationRestricted != _isRestricted, "State already set");

310:          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");

```


*GitHub* : [81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L81-L84),[105](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L105),[119](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L119),[120](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L120),[151](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L151),[254](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L254),[301](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L301),[310](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L310)

```solidity
File: src/asD.sol

54:           require(returnCode == 0, "Error when minting");

64:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem-underlying

81:               require(_amount <= maximumWithdrawable, "Too many tokens requested");

86:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [54](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L54),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L64),[81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L81),[86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86)
### [G&#x2011;25] Using `private` rather than `public`, saves gas
For constants, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*There are 18 instance(s) of this issue:*

```solidity
File: src/Market.sol

14:      uint256 public constant NFT_FEE_BPS = 1_000; // 10%

15:      uint256 public constant HOLDER_CUT_BPS = 3_300; // 33%

16:      uint256 public constant CREATOR_CUT_BPS = 3_300; // 33%

20:      IERC20 public immutable token;

27:      uint256 public shareCount;

30:      mapping(string => uint256) public shareIDs;

43:      mapping(uint256 => ShareData) public shareData;

46:      mapping(uint256 => address) public shareBondingCurves;

49:      mapping(address => bool) public whitelistedBondingCurves;

52:      mapping(uint256 => mapping(address => uint256)) public tokensByAddress;

55:      mapping(uint256 => mapping(address => uint256)) public rewardsLastClaimedValue;

58:      uint256 public platformPool;

61:      bool public shareCreationRestricted = true;

64:      mapping(address => bool) public whitelistedShareCreators;

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L14-L14),[15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L15-L15),[16](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L16-L16),[20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L20-L20),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L27-L27),[30](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L30-L30),[43](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L43-L43),[46](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L46-L46),[49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49-L49),[52](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L52-L52),[55](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L55-L55),[58](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L58-L58),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L61),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L64)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

8:       uint256 public immutable priceIncrease;

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L8-L8)

```solidity
File: src/asD.sol

15:      address public immutable cNote; // Reference to the cNOTE token

```


*GitHub* : [15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L15-L15)

```solidity
File: src/asDFactory.sol

12:      address public immutable cNote;

15:      mapping(address => bool) public isAsD;

```


*GitHub* : [12](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L12-L12),[15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L15-L15)### NonCritical Risk Issues <a name="01"></a>


### [N&#x2011;01] `address`es shouldn't be hard-coded
It is often better to declare `address`es as `immutable`, and assign them via constructor arguments. This allows the code to remain the same across deployments on different networks, and avoids recompilation when addresses need to change.

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

95:              Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);

```


*GitHub* : [95](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L95-L95)

```solidity
File: src/asD.sol

39:              Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);

```


*GitHub* : [39](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L39-L39)

```solidity
File: src/asDFactory.sol

28:              Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);

```


*GitHub* : [28](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L28-L28)
### [N&#x2011;02] `constant`s should be defined rather than using magic numbers
Even [assembly](https://github.com/code-423n4/2022-05-opensea-seaport/blob/9d7ce4d08bf3c3010304a0476a785c70c0e90ae7/contracts/lib/TokenTransferrer.sol#L35-L39) can benefit from using readable constants instead of hex/numeric literals

*There are 14 instance(s) of this issue:*

```solidity
File: src/Market.sol

93:          if (block.chainid == 7700 || block.chainid == 7701) {

93:          if (block.chainid == 7700 || block.chainid == 7701) {

197:         fee = (priceForOne * _amount * NFT_FEE_BPS) / 10_000;

276:             1e18;

285:         uint256 shareHolderFee = (_fee * HOLDER_CUT_BPS) / 10_000;

286:         uint256 shareCreatorFee = (_fee * CREATOR_CUT_BPS) / 10_000;

290:             shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;

```


*GitHub* : [93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93),[93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93),[197](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L197-L197),[276](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L276-L276),[285](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L285-L285),[286](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L286-L286),[290](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L290-L290)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

23:              fee += (getFee(i) * tokenPrice) / 1e18;

35:          return 1e17 / divisor;

```


*GitHub* : [23](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L23-L23),[35](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L35-L35)

```solidity
File: src/asD.sol

37:          if (block.chainid == 7700 || block.chainid == 7701) {

37:          if (block.chainid == 7700 || block.chainid == 7701) {

76:              1e28 -

```


*GitHub* : [37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37),[37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37),[76](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L76-L76)

```solidity
File: src/asDFactory.sol

26:          if (block.chainid == 7700 || block.chainid == 7701) {

26:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26),[26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26)
### [N&#x2011;03] `if`-statement can be converted to a ternary
The code can be made more compact while also increasing readability by converting the following `if`-statements to ternaries (e.g. `foo += (x > y) ? a : b`)

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

29           if (shareCount > 1) {
30               divisor = log2(shareCount);
31           } else {
32               divisor = 1;
33:          }

```


*GitHub* : [29](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L29-L33)
### [N&#x2011;04] Assembly blocks should have extensive comments
Assembly blocks take a lot more time to audit than normal Solidity code, and often have gotchas and side-effects that the Solidity versions of the same code do not. Consider adding more comments explaining what is being done in every step of the assembly code, and describe why assembly is being used instead of Solidity.

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

44            assembly {
45                r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
46                r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
47                r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
48                r := or(r, shl(4, lt(0xffff, shr(r, x))))
49                r := or(r, shl(3, lt(0xff, shr(r, x))))
50                // forgefmt: disable-next-item
51                r := or(
52                    r,
53                    byte(
54                        and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
55                        0x0706060506020504060203020504030106050205030304010505030400000000
56                    )
57                )
58:           }

```


*GitHub* : [44](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L44-L58)
### [N&#x2011;05] Avoid the use of sensitive terms
Use [alternative variants](https://www.zdnet.com/article/mysql-drops-master-slave-and-blacklist-whitelist-terminology/), e.g. allowlist/denylist instead of whitelist/blacklist

*There are 32 instance(s) of this issue:*

```solidity
File: src/Market.sol

49:       mapping(address => bool) public whitelistedBondingCurves;

64:       mapping(address => bool) public whitelistedShareCreators;

69:       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

309:      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

49:       mapping(address => bool) public whitelistedBondingCurves;

64:       mapping(address => bool) public whitelistedShareCreators;

69:       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

82:               !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),

105:          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");

106:          whitelistedBondingCurves[_bondingCurve] = _newState;

119:          require(whitelistedBondingCurves[_bondingCurve], "Bonding curve not whitelisted");

309:      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

309:      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

310:          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");

310:          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");

311:          whitelistedShareCreators[_address] = _isWhitelisted;

311:          whitelistedShareCreators[_address] = _isWhitelisted;

49:       mapping(address => bool) public whitelistedBondingCurves;

60:       /// @notice If true, only the whitelisted addresses can create shares

64:       mapping(address => bool) public whitelistedShareCreators;

69:       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

100:      /// @notice Whitelist or remove whitelist for a bonding curve.

101:      /// @dev Whitelisting status is only checked when adding a share

101:      /// @dev Whitelisting status is only checked when adding a share

103:      /// @param _newState True if whitelisted, false if not

103:      /// @param _newState True if whitelisted, false if not

112:      /// @param _bondingCurve Address of the bonding curve, has to be whitelisted

112:      /// @param _bondingCurve Address of the bonding curve, has to be whitelisted

306:      /// @notice Adds or removes an address from the whitelist of share creators

308:      /// @param _isWhitelisted True if whitelisted, false if not

308:      /// @param _isWhitelisted True if whitelisted, false if not

309:      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

```


*GitHub* : [49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64),[69](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L69),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309),[49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64),[69](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L69),[82](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L82),[105](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L105),[106](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L106),[119](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L119),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309),[310](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L310),[310](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L310),[311](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L311),[311](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L311),[49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L60),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64),[69](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L69),[100](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L100),[101](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L101),[101](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L101),[103](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L103),[103](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L103),[112](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L112),[112](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L112),[306](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L306),[308](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L308),[308](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L308),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309)
### [N&#x2011;06] Consider adding a block/deny-list
Doing so will significantly increase centralization, but will help to prevent hackers from using stolen tokens

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit IERC1155MetadataURI handles tokens
10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/asD.sol

/// @audit ERC20 handles tokens
11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)
### [N&#x2011;07] Consider adding emergency-stop functionality
Adding a way to quickly halt protocol functionality in an emergency, rather than having to pause individual contracts one-by-one, will make in-progress hack mitigation faster and much less stressful.

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;08] Consider adding formal verification proofs
Consider using formal verification to mathematically prove that your code does what is intended, and does not have any edge cases with unexpected behavior. The solidity compiler itself has this functionality [built in](https://docs.soliditylang.org/en/latest/smtchecker.html#smtchecker-and-formal-verification)

*There are 1 instance(s) of this issue:*

```solidity
File: Various Files


```


*GitHub* : [various](https://github.com/code-423n4/2023-11-canto/tree/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts)
### [N&#x2011;09] Consider defining system-wide constants in a single file

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

14:      uint256 public constant NFT_FEE_BPS = 1_000; // 10%

15:      uint256 public constant HOLDER_CUT_BPS = 3_300; // 33%

16:      uint256 public constant CREATOR_CUT_BPS = 3_300; // 33%

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L14-L14),[15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L15-L15),[16](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L16-L16)
### [N&#x2011;10] Consider disabling `renounceOwnership()`
If the plan for your project does not include eventually giving up all ownership control, consider overwriting OpenZeppelin's `Ownable`'s `renounceOwnership()` function in order to disable it.

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit Ownable.renounceOwnership()
10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/asD.sol

/// @audit Ownable.renounceOwnership()
11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

/// @audit Ownable.renounceOwnership()
8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;11] Consider making contracts `Upgradeable`
This allows for bugs to be fixed in production, at the expense of _significantly_ increasing centralization.

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;12] Consider moving `msg.sender` checks to a common authorization `modifier`

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

151:         require(shareData[_id].creator != msg.sender, "Creator cannot buy");

254:         require(shareData[_id].creator == msg.sender, "Not creator");

```


*GitHub* : [151](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L151-L151),[254](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L254-L254)
### [N&#x2011;13] Consider using `delete` rather than assigning zero/false to clear values
The `delete` keyword more closely matches the semantics of what is being done, and draws more attention to the changing of state, which may lead to a more thorough audit of its associated logic

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

256:          shareData[_id].shareCreatorPool = 0;

```


*GitHub* : [256](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L256)
### [N&#x2011;14] Consider using a `struct` rather than having many function input parameters

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

28       constructor(
29           string memory _name,
30           string memory _symbol,
31           address _owner,
32           address _cNote,
33           address _csrRecipient
34:      ) ERC20(_name, _symbol) {

```


*GitHub* : [28](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L28-L34)
### [N&#x2011;15] Consider using named mappings
Consider moving to solidity version 0.8.18 or later, and using [named mappings](https://ethereum.stackexchange.com/a/145555) to make it easier to understand the purpose of each mapping

*There are 10 instance(s) of this issue:*

```solidity
File: src/Market.sol

30:      mapping(string => uint256) public shareIDs;

43:      mapping(uint256 => ShareData) public shareData;

46:      mapping(uint256 => address) public shareBondingCurves;

49:      mapping(address => bool) public whitelistedBondingCurves;

52:      mapping(uint256 => mapping(address => uint256)) public tokensByAddress;

52:      mapping(uint256 => mapping(address => uint256)) public tokensByAddress;

55:      mapping(uint256 => mapping(address => uint256)) public rewardsLastClaimedValue;

55:      mapping(uint256 => mapping(address => uint256)) public rewardsLastClaimedValue;

64:      mapping(address => bool) public whitelistedShareCreators;

```


*GitHub* : [30](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L30-L30),[43](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L43-L43),[46](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L46-L46),[49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49-L49),[52](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L52-L52),[52](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L52-L52),[55](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L55-L55),[55](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L55-L55),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L64)

```solidity
File: src/asDFactory.sol

15:      mapping(address => bool) public isAsD;

```


*GitHub* : [15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L15-L15)
### [N&#x2011;16] Constants in comparisons should appear on the left side
Doing so will prevent [typo bugs](https://www.moserware.com/2008/01/constants-on-left-are-better-but-this.html)

*There are 11 instance(s) of this issue:*

```solidity
File: src/Market.sol

93:          if (block.chainid == 7700 || block.chainid == 7701) {

93:          if (block.chainid == 7700 || block.chainid == 7701) {

120:         require(shareIDs[_shareName] == 0, "Share already exists");

```


*GitHub* : [93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93),[93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93),[120](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L120-L120)

```solidity
File: src/asD.sol

37:          if (block.chainid == 7700 || block.chainid == 7701) {

37:          if (block.chainid == 7700 || block.chainid == 7701) {

54:          require(returnCode == 0, "Error when minting");

64:          require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem-underlying

78:          if (_amount == 0) {

86:          require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37),[37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37),[54](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L54-L54),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L64-L64),[78](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L78-L78),[86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86-L86)

```solidity
File: src/asDFactory.sol

26:          if (block.chainid == 7700 || block.chainid == 7701) {

26:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26),[26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26)
### [N&#x2011;17] Contract should expose an `interface`
The `contract`s should expose an `interface` so that other projects can more easily integrate with it, without having to develop their own non-standard variants.

*There are 18 instance(s) of this issue:*

```solidity
File: src/Market.sol

104:     function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {

114      function createNewShare(
115          string memory _shareName,
116          address _bondingCurve,
117          string memory _metadataURI
118:     ) external onlyShareCreator returns (uint256 id) {

132:     function getBuyPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {

141:     function getSellPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {

150:     function buy(uint256 _id, uint256 _amount) external {

174:     function sell(uint256 _id, uint256 _amount) external {

194:     function getNFTMintingPrice(uint256 _id, uint256 _amount) public view returns (uint256 fee) {

203:     function mintNFT(uint256 _id, uint256 _amount) external {

226:     function burnNFT(uint256 _id, uint256 _amount) external {

244:     function claimPlatformFee() external onlyOwner {

253:     function claimCreatorFee(uint256 _id) external {

263:     function claimHolderFee(uint256 _id) external {

300:     function restrictShareCreation(bool _isRestricted) external onlyOwner {

309:     function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

```


*GitHub* : [104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104-L104),[114](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L114-L118),[132](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L132-L132),[141](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L141-L141),[150](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L150-L150),[174](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L174-L174),[194](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L194-L194),[203](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L203-L203),[226](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L226-L226),[244](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L244-L244),[253](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L253-L253),[263](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L263-L263),[300](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L300-L300),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309-L309)

```solidity
File: src/asD.sol

47:      function mint(uint256 _amount) external {

60:      function burn(uint256 _amount) external {

72:      function withdrawCarry(uint256 _amount) external onlyOwner {

```


*GitHub* : [47](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L47-L47),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L60-L60),[72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L72-L72)

```solidity
File: src/asDFactory.sol

33:      function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33)
### [N&#x2011;18] Contracts should have full test coverage
While 100% code coverage does not guarantee that there are no bugs, it often will catch easy-to-find bugs, and will ensure that there are fewer regressions when the code invariably has to be modified. Furthermore, in order to get full coverage, code authors will often have to re-organize their code so that it is more modular, so that each component can be tested separately, which reduces interdependencies between modules and layers, and makes for code that is easier to reason about and audit.

*There are 1 instance(s) of this issue:*

```solidity
File: Various Files


```


*GitHub* : [various](https://github.com/code-423n4/2023-11-canto/tree/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts)
### [N&#x2011;19] Custom errors should be used rather than `revert()`/`require()`
Custom errors are available from solidity version 0.8.4. Custom errors are more easily processed in `try`-`catch` blocks, and are easier to re-use and maintain.

*There are 12 instance(s) of this issue:*

```solidity
File: src/Market.sol

81            require(
82                !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83                "Not allowed"
84:           );

105:          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");

119:          require(whitelistedBondingCurves[_bondingCurve], "Bonding curve not whitelisted");

120:          require(shareIDs[_shareName] == 0, "Share already exists");

151:          require(shareData[_id].creator != msg.sender, "Creator cannot buy");

254:          require(shareData[_id].creator == msg.sender, "Not creator");

301:          require(shareCreationRestricted != _isRestricted, "State already set");

310:          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");

```


*GitHub* : [81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L81-L84),[105](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L105),[119](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L119),[120](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L120),[151](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L151),[254](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L254),[301](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L301),[310](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L310)

```solidity
File: src/asD.sol

54:           require(returnCode == 0, "Error when minting");

64:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem-underlying

81:               require(_amount <= maximumWithdrawable, "Too many tokens requested");

86:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [54](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L54),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L64),[81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L81),[86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86)
### [N&#x2011;20] Duplicated `require()`/`revert()` checks should be refactored to a modifier or function
The compiler will inline the function, which will avoid `JUMP` instructions usually associated with functions

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

86:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86)
### [N&#x2011;21] Event is not properly `indexed`
Index event fields make the field more quickly accessible [to off-chain tools](https://ethereum.stackexchange.com/questions/40396/can-somebody-please-explain-the-concept-of-event-indexing) that parse events. This is especially useful when it comes to filtering based on an address. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Where applicable, each `event` should use three `indexed` fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three applicable fields, all of the applicable fields should be indexed.

*There are 1 instance(s) of this issue:*

```solidity
File: src/asDFactory.sol

20:       event CreatedToken(address token, string symbol, string name, address creator);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L20)
### [N&#x2011;22] Events are missing sender information
When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the `msg.sender` the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

107:         emit BondingCurveStateChange(_bondingCurve, _newState);

303:         emit ShareCreationRestricted(_isRestricted);

```


*GitHub* : [107](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L107-L107),[303](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L303-L303)

```solidity
File: src/asD.sol

89:          emit CarryWithdrawal(_amount);

```


*GitHub* : [89](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L89-L89)
### [N&#x2011;23] Events may be emitted out of order due to reentrancy
Ensure that events follow the best practice of check-effects-interaction, and are emitted before external calls

*There are 8 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit safeTransferFrom() prior to emission
168:         emit SharesBought(_id, msg.sender, _amount, price, fee);

/// @audit safeTransferFrom() prior to emission
188:         emit SharesSold(_id, msg.sender, _amount, price, fee);

/// @audit safeTransferFrom() prior to emission
220:         emit NFTsCreated(_id, msg.sender, _amount, fee);

/// @audit safeTransferFrom() prior to emission
240:         emit NFTsBurned(_id, msg.sender, _amount, fee);

/// @audit safeTransferFrom() prior to emission
248:         emit PlatformFeeClaimed(msg.sender, amount);

/// @audit safeTransferFrom() prior to emission
258:         emit CreatorFeeClaimed(msg.sender, _id, amount);

/// @audit safeTransferFrom() prior to emission
269:         emit HolderFeeClaimed(msg.sender, _id, amount);

```


*GitHub* : [168](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L168-L168),[188](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L188-L188),[220](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L220-L220),[240](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L240-L240),[248](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L248-L248),[258](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L258-L258),[269](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L269-L269)

```solidity
File: src/asD.sol

/// @audit exchangeRateCurrent() prior to emission
89:          emit CarryWithdrawal(_amount);

```


*GitHub* : [89](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L89-L89)
### [N&#x2011;24] Large multiples of ten should use scientific notation
Large multiples of ten should use scientific notation (e.g. `1e6`) rather than decimal literals (e.g. `1000000`), for readability

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit 1_000
14:      uint256 public constant NFT_FEE_BPS = 1_000; // 10%

/// @audit 10_000
197:         fee = (priceForOne * _amount * NFT_FEE_BPS) / 10_000;

/// @audit 10_000
285:         uint256 shareHolderFee = (_fee * HOLDER_CUT_BPS) / 10_000;

/// @audit 10_000
286:         uint256 shareCreatorFee = (_fee * CREATOR_CUT_BPS) / 10_000;

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L14-L14),[197](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L197-L197),[285](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L285-L285),[286](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L286-L286)
### [N&#x2011;25] Large numeric literals should use underscores for readability

*There are 6 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit 7700
/// @audit 7701
93:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93),[93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93)

```solidity
File: src/asD.sol

/// @audit 7700
/// @audit 7701
37:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37),[37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37)

```solidity
File: src/asDFactory.sol

/// @audit 7700
/// @audit 7701
26:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26),[26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26)
### [N&#x2011;26] Large or complicated code bases should implement invariant tests
Large code bases, or code with lots of inline-assembly, complicated math, or complicated interactions between multiple contracts, should implement [invariant fuzzing tests](https://medium.com/coinmonks/smart-contract-fuzzing-d9b88e0b0a05). Invariant fuzzers such as Echidna require the test writer to come up with invariants which should not be violated under any circumstances, and the fuzzer tests various inputs and function calls to ensure that the invariants always hold. Even code with 100% code coverage can still have bugs due to the order of the operations a user performs, and invariant fuzzers, with properly and extensively-written invariants, can close this testing gap significantly.

*There are 1 instance(s) of this issue:*

```solidity
File: Various Files


```


*GitHub* : [various](https://github.com/code-423n4/2023-11-canto/tree/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts)
### [N&#x2011;27] Memory-safe annotation preferred over comment variant
The memory-safe annotation (`assembly ("memory-safe") { ... }`), available starting in Solidity version 0.8.13 is preferred over the comment variant, which will be removed in a future breaking [release](https://docs.soliditylang.org/en/v0.8.13/assembly.html#memory-safety). The comment variant is only meant for externalized library code that needs to work in earlier versions (e.g. `SafeTransferLib` needs to be able to be used in many different versions).

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

43           /// @solidity memory-safe-assembly
44           assembly {
45               r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
46               r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
47               r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
48               r := or(r, shl(4, lt(0xffff, shr(r, x))))
49               r := or(r, shl(3, lt(0xff, shr(r, x))))
50               // forgefmt: disable-next-item
51               r := or(
52                   r,
53                   byte(
54                       and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
55                       0x0706060506020504060203020504030106050205030304010505030400000000
56                   )
57               )
58:          }

```


*GitHub* : [43](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L43-L58)
### [N&#x2011;28] Missing checks constructor/initializer assignments
Consider whether reasonable bounds checks for variables would be useful

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit _priceIncrease
11:          priceIncrease = _priceIncrease;

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L11-L11)
### [N&#x2011;29] Missing event and or timelock for critical parameter change
Events help non-contract tools to track changes, and timelocks prevent users from being surprised by changes

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

311:         whitelistedShareCreators[_address] = _isWhitelisted;

```


*GitHub* : [311](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L311-L311)
### [N&#x2011;30] NatSpec: Contract declarations should have `@author` tags

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;31] NatSpec: Contract declarations should have `@dev` tags
`@dev` is used to explain extra details to developers

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;32] NatSpec: Contract declarations should have `@notice` tags
`@notice` is used to explain to end users what the contract does, and the compiler interprets `///` or `/**` comments (but not `//` or `/*`) as this tag if one wasn't explicitly provided. Note that the NatSpec comment must be _above_ the contract definition.

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;33] NatSpec: Contract declarations should have `@title` tags

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;34] NatSpec: Contract declarations should have descriptions
e.g. `@dev` or `@notice`, and it must appear above the contract definition braces in order to be identified by the compiler as NatSpec

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10   contract Market is ERC1155, Ownable2Step {
11       /*//////////////////////////////////////////////////////////////
12                                    CONSTANTS
13:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10-L13)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;35] NatSpec: Event `@param` tag is missing

*There are 38 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit Missing '@param curve'
/// @audit Missing '@param isWhitelisted'
59   
60       /// @notice If true, only the whitelisted addresses can create shares
61       bool public shareCreationRestricted = true;
62   
63       /// @notice List of addresses that can add new shares when shareCreationRestricted is true
64       mapping(address => bool) public whitelistedShareCreators;
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69:      event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

/// @audit Missing '@param id'
/// @audit Missing '@param name'
/// @audit Missing '@param bondingCurve'
/// @audit Missing '@param creator'
60       /// @notice If true, only the whitelisted addresses can create shares
61       bool public shareCreationRestricted = true;
62   
63       /// @notice List of addresses that can add new shares when shareCreationRestricted is true
64       mapping(address => bool) public whitelistedShareCreators;
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70:      event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);

/// @audit Missing '@param id'
/// @audit Missing '@param buyer'
/// @audit Missing '@param amount'
/// @audit Missing '@param price'
/// @audit Missing '@param fee'
61       bool public shareCreationRestricted = true;
62   
63       /// @notice List of addresses that can add new shares when shareCreationRestricted is true
64       mapping(address => bool) public whitelistedShareCreators;
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71:      event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);

/// @audit Missing '@param id'
/// @audit Missing '@param seller'
/// @audit Missing '@param amount'
/// @audit Missing '@param price'
/// @audit Missing '@param fee'
62   
63       /// @notice List of addresses that can add new shares when shareCreationRestricted is true
64       mapping(address => bool) public whitelistedShareCreators;
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72:      event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);

/// @audit Missing '@param id'
/// @audit Missing '@param creator'
/// @audit Missing '@param amount'
/// @audit Missing '@param fee'
63       /// @notice List of addresses that can add new shares when shareCreationRestricted is true
64       mapping(address => bool) public whitelistedShareCreators;
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72       event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);
73:      event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);

/// @audit Missing '@param id'
/// @audit Missing '@param burner'
/// @audit Missing '@param amount'
/// @audit Missing '@param fee'
64       mapping(address => bool) public whitelistedShareCreators;
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72       event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);
73       event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);
74:      event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);

/// @audit Missing '@param claimer'
/// @audit Missing '@param amount'
65   
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72       event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);
73       event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);
74       event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);
75:      event PlatformFeeClaimed(address indexed claimer, uint256 amount);

/// @audit Missing '@param claimer'
/// @audit Missing '@param id'
/// @audit Missing '@param amount'
66       /*//////////////////////////////////////////////////////////////
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72       event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);
73       event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);
74       event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);
75       event PlatformFeeClaimed(address indexed claimer, uint256 amount);
76:      event CreatorFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

/// @audit Missing '@param claimer'
/// @audit Missing '@param id'
/// @audit Missing '@param amount'
67                                    EVENTS
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72       event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);
73       event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);
74       event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);
75       event PlatformFeeClaimed(address indexed claimer, uint256 amount);
76       event CreatorFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);
77:      event HolderFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

/// @audit Missing '@param isRestricted'
68       //////////////////////////////////////////////////////////////*/
69       event BondingCurveStateChange(address indexed curve, bool isWhitelisted);
70       event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);
71       event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);
72       event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);
73       event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);
74       event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);
75       event PlatformFeeClaimed(address indexed claimer, uint256 amount);
76       event CreatorFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);
77       event HolderFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);
78:      event ShareCreationRestricted(bool isRestricted);

```


*GitHub* : [59](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L59-L69),[59](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L59-L69),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L60-L70),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L60-L70),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L60-L70),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L60-L70),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L71),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L71),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L71),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L71),[61](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L61-L71),[62](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L62-L72),[62](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L62-L72),[62](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L62-L72),[62](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L62-L72),[62](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L62-L72),[63](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L63-L73),[63](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L63-L73),[63](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L63-L73),[63](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L63-L73),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L74),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L74),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L74),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L74),[65](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L65-L75),[65](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L65-L75),[66](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L66-L76),[66](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L66-L76),[66](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L66-L76),[67](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L67-L77),[67](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L67-L77),[67](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L67-L77),[68](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L68-L78)

```solidity
File: src/asD.sol

/// @audit Missing '@param amount'
11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14       //////////////////////////////////////////////////////////////*/
15       address public immutable cNote; // Reference to the cNOTE token
16   
17       /*//////////////////////////////////////////////////////////////
18                                    EVENTS
19       //////////////////////////////////////////////////////////////*/
20:      event CarryWithdrawal(uint256 amount);

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L20)

```solidity
File: src/asDFactory.sol

/// @audit Missing '@param token'
/// @audit Missing '@param symbol'
/// @audit Missing '@param name'
/// @audit Missing '@param creator'
10                                    STATE
11       //////////////////////////////////////////////////////////////*/
12       address public immutable cNote;
13   
14       /// @notice Stores the addresses of all created tokens, allowing third-party contracts to check if an address is a legit token
15       mapping(address => bool) public isAsD;
16   
17       /*//////////////////////////////////////////////////////////////
18                                    EVENTS
19       //////////////////////////////////////////////////////////////*/
20:      event CreatedToken(address token, string symbol, string name, address creator);

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L10-L20),[10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L10-L20),[10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L10-L20),[10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L10-L20)
### [N&#x2011;36] NatSpec: Event declarations should have descriptions

*There are 12 instance(s) of this issue:*

```solidity
File: src/Market.sol

69:      event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

70:      event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);

71:      event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);

72:      event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);

73:      event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);

74:      event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);

75:      event PlatformFeeClaimed(address indexed claimer, uint256 amount);

76:      event CreatorFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

77:      event HolderFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

78:      event ShareCreationRestricted(bool isRestricted);

```


*GitHub* : [69](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L69-L69),[70](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L70-L70),[71](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L71-L71),[72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L72-L72),[73](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L73-L73),[74](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L74-L74),[75](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L75-L75),[76](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L76-L76),[77](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L77-L77),[78](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L78-L78)

```solidity
File: src/asD.sol

20:      event CarryWithdrawal(uint256 amount);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L20-L20)

```solidity
File: src/asDFactory.sol

20:      event CreatedToken(address token, string symbol, string name, address creator);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L20-L20)
### [N&#x2011;37] NatSpec: Function `@param` tag is missing

*There are 11 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit Missing '@param _id'
272:     function _getRewardsSinceLastClaim(uint256 _id) internal view returns (uint256 amount) {

/// @audit Missing '@param _id'
279      /// @notice Splits the fee among the share holder, creator and platform
280      function _splitFees(
281:         uint256 _id,

/// @audit Missing '@param _fee'
279      /// @notice Splits the fee among the share holder, creator and platform
280      function _splitFees(
281          uint256 _id,
282:         uint256 _fee,

/// @audit Missing '@param _tokenCount'
279      /// @notice Splits the fee among the share holder, creator and platform
280      function _splitFees(
281          uint256 _id,
282          uint256 _fee,
283:         uint256 _tokenCount

```


*GitHub* : [272](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L272-L272),[279](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L279-L281),[279](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L279-L282),[279](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L279-L283)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit Missing '@param _priceIncrease'
10:      constructor(uint256 _priceIncrease) {

/// @audit Missing '@param shareCount'
/// @audit Missing '@param amount'
14:      function getPriceAndFee(uint256 shareCount, uint256 amount)

/// @audit Missing '@param shareCount'
27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

/// @audit Missing '@param x'
38       /// @dev Returns the log2 of `x`.
39       /// Equivalent to computing the index of the most significant bit (MSB) of `x`.
40       /// Returns 0 if `x` is zero.
41       /// @notice Copied from Solady: https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol
42:      function log2(uint256 x) internal pure returns (uint256 r) {

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L10-L10),[14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L14),[14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L14),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27),[38](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L38-L42)

```solidity
File: src/asDFactory.sol

/// @audit Missing '@param _name'
/// @audit Missing '@param _symbol'
33:      function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33),[33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33)
### [N&#x2011;38] NatSpec: Function `@return` tag is missing

*There are 12 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit Missing '@return id'
110      /// @notice Creates a new share
111      /// @param _shareName Name of the share
112      /// @param _bondingCurve Address of the bonding curve, has to be whitelisted
113      /// @param _metadataURI URI of the metadata
114      function createNewShare(
115          string memory _shareName,
116          address _bondingCurve,
117          string memory _metadataURI
118:     ) external onlyShareCreator returns (uint256 id) {

/// @audit Missing '@return price'
/// @audit Missing '@return fee'
129      /// @notice Returns the price and fee for buying a given number of shares.
130      /// @param _id The ID of the share
131      /// @param _amount The number of shares to buy.
132:     function getBuyPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {

/// @audit Missing '@return fee'
/// @audit Missing '@return price'
138      /// @notice Returns the price and fee for selling a given number of shares.
139      /// @param _id The ID of the share
140      /// @param _amount The number of shares to sell.
141:     function getSellPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {

/// @audit Missing '@return fee'
191      /// @notice Returns the price and fee for minting a given number of NFTs.
192      /// @param _id The ID of the share
193      /// @param _amount The number of NFTs to mint.
194:     function getNFTMintingPrice(uint256 _id, uint256 _amount) public view returns (uint256 fee) {

/// @audit Missing '@return amount'
272:     function _getRewardsSinceLastClaim(uint256 _id) internal view returns (uint256 amount) {

```


*GitHub* : [110](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L110-L118),[129](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L129-L132),[129](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L129-L132),[138](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L138-L141),[138](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L138-L141),[191](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L191-L194),[272](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L272-L272)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit Missing '@return price'
/// @audit Missing '@return fee'
14       function getPriceAndFee(uint256 shareCount, uint256 amount)
15           external
16           view
17           override
18           returns (uint256 price, uint256 fee)
19:      {

/// @audit Missing '@return  '
27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

/// @audit Missing '@return r'
38       /// @dev Returns the log2 of `x`.
39       /// Equivalent to computing the index of the most significant bit (MSB) of `x`.
40       /// Returns 0 if `x` is zero.
41       /// @notice Copied from Solady: https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol
42:      function log2(uint256 x) internal pure returns (uint256 r) {

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27),[38](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L38-L42)

```solidity
File: src/asDFactory.sol

/// @audit Missing '@return  '
33:      function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33)
### [N&#x2011;39] NatSpec: Function declarations should have `@notice` tags
`@notice` is used to explain to end users what the function does, and the compiler interprets `///` or `/**` comments (but not `//` or `/*`) as this tag if one wasn't explicitly provided

*There are 4 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

10:      constructor(uint256 _priceIncrease) {

14       function getPriceAndFee(uint256 shareCount, uint256 amount)
15           external
16           view
17           override
18           returns (uint256 price, uint256 fee)
19:      {

27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L10-L10),[14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27)

```solidity
File: src/asDFactory.sol

33:      function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33)
### [N&#x2011;40] NatSpec: Function declarations should have descriptions

*There are 4 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

10:      constructor(uint256 _priceIncrease) {

14       function getPriceAndFee(uint256 shareCount, uint256 amount)
15           external
16           view
17           override
18           returns (uint256 price, uint256 fee)
19:      {

27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L10-L10),[14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27)

```solidity
File: src/asDFactory.sol

33:      function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [33](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L33-L33)
### [N&#x2011;41] NatSpec: Modifier declarations should have `@notice` tags
`@notice` is used to explain to end users what the modifer does, and the compiler interprets `///` or `/**` comments (but not `//` or `/*`) as this tag if one wasn't explicitly provided

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

80       modifier onlyShareCreator() {
81           require(
82               !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83               "Not allowed"
84           );
85           _;
86:      }

```


*GitHub* : [80](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L80-L86)
### [N&#x2011;42] NatSpec: Modifier declarations should have descriptions

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

80       modifier onlyShareCreator() {
81           require(
82               !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83               "Not allowed"
84           );
85           _;
86:      }

```


*GitHub* : [80](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L80-L86)
### [N&#x2011;43] NatSpec: Public state variable declarations should have descriptions
e.g. `@notice` [tags](https://docs.soliditylang.org/en/latest/natspec-format.html#tags)

*There are 6 instance(s) of this issue:*

```solidity
File: src/Market.sol

14:      uint256 public constant NFT_FEE_BPS = 1_000; // 10%

15:      uint256 public constant HOLDER_CUT_BPS = 3_300; // 33%

16:      uint256 public constant CREATOR_CUT_BPS = 3_300; // 33%

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L14-L14),[15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L15-L15),[16](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L16-L16)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

8:       uint256 public immutable priceIncrease;

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L8-L8)

```solidity
File: src/asD.sol

15:      address public immutable cNote; // Reference to the cNOTE token

```


*GitHub* : [15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L15-L15)

```solidity
File: src/asDFactory.sol

12:      address public immutable cNote;

```


*GitHub* : [12](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L12-L12)
### [N&#x2011;44] NatSpec: Use `@inheritdoc` to inherit the NatSpec of the base function

*There are 2 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

14       function getPriceAndFee(uint256 shareCount, uint256 amount)
15           external
16           view
17           override
18           returns (uint256 price, uint256 fee)
19:      {

27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27)
### [N&#x2011;45] Non-library/interface files should use fixed compiler versions, not floating ones
Note that some file names may indicate an interface, but actually contain abstract contracts

*There are 2 instance(s) of this issue:*

```solidity
File: src/asD.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L2-L2)

```solidity
File: src/asDFactory.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2-L2)
### [N&#x2011;46] Ownable contract never uses `onlyOwner` modifier
Consider whether the contract really needs to be `Ownable`

*There are 1 instance(s) of this issue:*

```solidity
File: src/asDFactory.sol

/// @audit Ownable2Step
8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;47] Style guide: Contract names should use CamelCase
According to the Solidity [style guide](https://docs.soliditylang.org/en/latest/style-guide.html#contract-and-library-names) contract names should be in CamelCase and should match their file names.

*There are 2 instance(s) of this issue:*

```solidity
File: src/asD.sol

11   contract asD is ERC20, Ownable2Step {
12       /*//////////////////////////////////////////////////////////////
13                                    STATE
14:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11-L14)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [N&#x2011;48] Style guide: Function ordering does not follow the Solidity style guide
According to the [Solidity style guide](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-functions), functions should be laid out in the following order :`constructor()`, `receive()`, `fallback()`, `external`, `public`, `internal`, `private`, but the cases below do not follow this pattern

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit getSellPrice() came earlier
150:      function buy(uint256 _id, uint256 _amount) external {

/// @audit getNFTMintingPrice() came earlier
203:      function mintNFT(uint256 _id, uint256 _amount) external {

/// @audit _splitFees() came earlier
300:      function restrictShareCreation(bool _isRestricted) external onlyOwner {

```


*GitHub* : [150](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L150),[203](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L203),[300](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L300)
### [N&#x2011;49] Style guide: Lines are too long
Usually lines in source code are limited to [80](https://softwareengineering.stackexchange.com/questions/148677/why-is-80-characters-the-standard-limit-for-code-width) characters. Today's screens are much larger so it's reasonable to stretch this in some cases. The solidity style guide recommends a maximumum line length of [120 characters](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#maximum-line-length), so the lines below should be split when they reach that length.

*There are 11 instance(s) of this issue:*

```solidity
File: src/Market.sol

34:           uint256 tokensInCirculation; // Number of outstanding tokens - tokens that are minted as NFT, i.e. the number of tokens that receive fees

35:           uint256 shareHolderRewardsPerTokenScaled; // Accrued funds for the share holder per token, multiplied by 1e18 to avoid precision loss

155:          // The rewardsLastClaimedValue then needs to be updated with the new value such that the user cannot claim fees of this buy

231:          // The user does not get the proportional rewards for the burning (unless they have additional tokens that are not in the NFT)

```


*GitHub* : [34](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L34),[35](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L35),[155](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L155),[231](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L231)

```solidity
File: src/asD.sol

64:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem-underlying

71:       /// @dev The function checks that the owner does not withdraw too much NOTE, i.e. that a 1:1 NOTE:asD exchange rate can be maintained after the withdrawal

73:           uint256 exchangeRate = CTokenInterface(cNote).exchangeRateCurrent(); // Scaled by 1 * 10^(18 - 8 + Underlying Token Decimals), i.e. 10^(28) in our case

74:           // The amount of cNOTE the contract has to hold (based on the current exchange rate which is always increasing) such that it is always possible to receive 1 NOTE when burning 1 asD

84:           // But we do not handle this case specifically, as the only consequence is that the owner wastes a bit of gas when there is nothing to withdraw

86:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L64),[71](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L71),[73](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L73),[74](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L74),[84](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L84),[86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86)

```solidity
File: src/asDFactory.sol

14:       /// @notice Stores the addresses of all created tokens, allowing third-party contracts to check if an address is a legit token

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L14)
### [N&#x2011;50] Style guide: Non-`external`/`public` function names should begin with an underscore
According to the Solidity Style Guide, non-`external`/`public` function names should begin with an [underscore](https://docs.soliditylang.org/en/latest/style-guide.html#underscore-prefix-for-non-external-functions-and-variables)

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

42:      function log2(uint256 x) internal pure returns (uint256 r) {

```


*GitHub* : [42](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L42-L42)
### [N&#x2011;51] Style guide: Variable names for `immutable`s should use CONSTANT_CASE
For `immutable` variable names, each word should use all capital letters, with underscores separating each word (CONSTANT_CASE)

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

20:      IERC20 public immutable token;

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L20-L20)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

8:       uint256 public immutable priceIncrease;

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L8-L8)
### [N&#x2011;52] Unused `public` contract variable
Note that there may be cases where a variable superficially appears to be used, but this is only because there are multiple definitions of the variable in different files. In such cases, the variable definition should be moved into a separate file. The instances below are the unused variables.

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

46:      mapping(uint256 => address) public shareBondingCurves;

```


*GitHub* : [46](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L46-L46)
### [N&#x2011;53] Unused import
The identifier is imported but never used within the file

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

/// @audit IasDFactory
5:   import {IasDFactory} from "../interface/IasDFactory.sol";

```


*GitHub* : [5](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L5-L5)
### [N&#x2011;54] Use of `override` is unnecessary
Starting with Solidity version [0.8.8](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding), using the `override` keyword when the function solely overrides an interface function, and the function doesn't exist in multiple base contracts, is unnecessary.

*There are 2 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

14       function getPriceAndFee(uint256 shareCount, uint256 amount)
15           external
16           view
17           override
18           returns (uint256 price, uint256 fee)
19:      {

27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27)
### [N&#x2011;55] Use the latest solidity (prior to 0.8.20 if on L2s) for deployment
```
When deploying contracts, you should use the latest released version of Solidity. Apart from exceptional cases, only the latest version receives security fixes.
```
https://docs.soliditylang.org/en/v0.8.20/

Since deployed contracts should not use floating pragmas, I've flagged all instances where a version prior to 0.8.19 is allowed by the version pragma

*There are 2 instance(s) of this issue:*

```solidity
File: src/asD.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L2-L2)

```solidity
File: src/asDFactory.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2-L2)
### [N&#x2011;56] Using `>`/`>=` without specifying an upper bound is unsafe
There _will_ be breaking changes in future versions of solidity, and at that point your code will no longer be compatable. While you may have the specific version to use in a configuration file, others that include your source files may not.

*There are 2 instance(s) of this issue:*

```solidity
File: src/asD.sol

2:    pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L2)

```solidity
File: src/asDFactory.sol

2:    pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2)### Disputed Risk Issues <a name="01"></a>


### [D&#x2011;01] ~~`approve()`/`safeApprove()` may revert if the current approval is not zero~~
The general rule is valid, but the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

51:          SafeERC20.safeApprove(note, cNote, _amount);

```


*GitHub* : [51](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L51-L51)
### [D&#x2011;02] ~~Avoid updating storage when the value hasn't changed~~
If the old value is equal to the new value, not re-storing the value will avoid a Gsreset (**2900 gas**), potentially at the expense of a Gcoldsload (**2100 gas**) or a Gwarmaccess (**100 gas**)

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

309      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {
310          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");
311          whitelistedShareCreators[_address] = _isWhitelisted;
312:     }

104      function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {
105          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");
106          whitelistedBondingCurves[_bondingCurve] = _newState;
107          emit BondingCurveStateChange(_bondingCurve, _newState);
108:     }

```


*GitHub* : [309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309-L312),[104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104-L108)
### [D&#x2011;03] ~~Avoid Zero to Non-Zero Storage Writes Where Possible~~
There is no actual actionable code suggestion being made for the provided cases

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

246:         platformPool = 0;

295:         platformPool += platformFee;

```


*GitHub* : [246](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L246-L246),[295](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L295-L295)
### [D&#x2011;04] ~~Bad bot rules~~
The titles below correspond to issues submitted by various bots, where the submitting bot solely submitted invalid findings (i.e. the submitter didn't filter the results of the rule), so they should be given extra scrutiny:
- **Max allowance is not compatible with all tokens** - internal approval for the contract's own balance, so the rule is pointing to the support **for** max allowance
- **increase/decrease allowance should be used instead of approve** - this is an internal approval function
- **Must approve or increase allowance first** - the rule is flagging all transferFrom() calls, without approval logic
- **Contract existence is not checked before low level call** - reading calldata, not making an external call
- **Empty function blocks** - the bot's removed the extensive comment documentation in the 'code blocks' it shows for these virtual functions used to allow child contracts to implement functionality, or are constructors
- **Utility contracts can be made into libraries** - all provided examples are invalid
- **Address values should be used through variables rather than used as literals** - none of the examples are of addresses
- **Employ Explicit Casting to Bytes or Bytes32 for Enhanced Code Clarity and Meaning** - the large majority of the examples are of multiple arguments, not just one
- **Some if-statement can be converted to a ternary** - you can't use a ternary when only one of the branches is a `return`
- **Addresses shouldn't be hard-coded** - none of these are addresses
- **State variables used within a function more than once should be cached to save gas** - none of these are state variables
- **Use storage instead of memory for structs/arrays** - these all are array call arguments, not arrays copied from storage
- **Use bitmap to save gas** - none of these are examples where bitmaps can be used
- **Consider merging sequential for loops** - the examples cannot be merged
- **Emitting storage values instead of the memory one.** - this is a gas finding, not a Low one
- **`selfbalance()` is cheaper than `address(this).balance`** - some bots submit the issue twice (under the heading `Use assembly when getting a contractundefineds balance of ETH`)
- **Imports could be organized more systematically** - a lot of bots are blindly checking for interfaces not coming first. That is not the only way of organizing imports, and most projects are doing it in a systematic, valid, way
- **Unused * definition** - some bots are reporting false positives for these rules. Check that it isn't used, or that if it's used, that there are two definitions, with one being unused
- **`internal` functions not called by the contract should be removed** - some bots are reporting false positives when the function is called by a child contract, rather than the defining contract
- **Change `public` to `external` for functions that are not called internally** - some bots are reporting false positives when the function is called by a child contract, rather than the defining contract
- **Avoid contract existence checks by using low level calls** - at least one bot isn't checking that the version is prior to 0.8.10
- **For Operations that will not overflow, you could use unchecked** - at least one bot is flagging every single line, which has nothing to do with using `unchecked`

Some of these have been raised as invalid in multiple contests, and the bot owners have not fixed them. Without penalties, they're unlikely to make any changes

*There are 2 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

2:   pragma solidity 0.8.19;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L2-L2)

```solidity
File: src/asDFactory.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2-L2)
### [D&#x2011;05] ~~Consider adding a block/deny-list~~
Contract doesn't handle tokens

*There are 2 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6    contract LinearBondingCurve is IBondingCurve {
7:       // By how much the price increases per share, provided in the token decimals

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6-L7)

```solidity
File: src/asDFactory.sol

8    contract asDFactory is Ownable2Step {
9        /*//////////////////////////////////////////////////////////////
10                                    STATE
11:      //////////////////////////////////////////////////////////////*/

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8-L11)
### [D&#x2011;06] ~~Constant decimal values~~
These instances have nothing to do with a token's decimals, so these findings are invalid

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

276:             1e18;

290:             shareData[_id].shareHolderRewardsPerTokenScaled += (shareHolderFee * 1e18) / _tokenCount;

```


*GitHub* : [276](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L276-L276),[290](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L290-L290)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

23:              fee += (getFee(i) * tokenPrice) / 1e18;

```


*GitHub* : [23](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L23-L23)
### [D&#x2011;07] ~~Constant redefined elsewhere~~
The general rule is valid, but the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
File: src/asDFactory.sol

/// @audit Seen in asD
12:      address public immutable cNote;

```


*GitHub* : [12](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L12-L12)
### [D&#x2011;08] ~~Contracts do not work with fee-on-transfer tokens~~
An ERC20 token being used, in and of itself, is not evidence of a fee-on-transfer issue; there must be other evidence that the balance accounting gets broken, and these lines do not contain such evidence.

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

92:          token = IERC20(_paymentToken);

```


*GitHub* : [92](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L92-L92)
### [D&#x2011;09] ~~Control structures do not follow the Solidity Style Guide~~
The instances below properly drop down to the next line when the arguments are too long

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

113       /// @param _metadataURI URI of the metadata
114       function createNewShare(
115:          string memory _shareName,

279       /// @notice Splits the fee among the share holder, creator and platform
280       function _splitFees(
281:          uint256 _id,

```


*GitHub* : [113](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L113-L115),[279](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L279-L281)
### [D&#x2011;10] ~~Default `bool` values are manually reset~~
Using delete instead of assigning zero/false to state variables does not save any extra gas with the optimizer [on](https://gist.github.com/IllIllI000/ef8ec3a70aede7f12433fe63dc418515#with-the-optimizer-set-at-200-runs) (saves 5-8 gas with optimizer completely off), so this finding is invalid, especially since if they were interested in gas savings, they'd have the optimizer enabled. Some bots are also flagging `true` rather than just `false`

*There are 1 instance(s) of this issue:*

```solidity
File: src/asDFactory.sol

35:          isAsD[address(createdToken)] = true;

```


*GitHub* : [35](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L35-L35)
### [D&#x2011;11] ~~Duplicated `require()`/`revert()` checks should be refactored to a modifier or function~~
This instance appears only once

*There are 10 instance(s) of this issue:*

```solidity
File: src/Market.sol

81            require(
82                !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),
83                "Not allowed"
84:           );

105:          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");

119:          require(whitelistedBondingCurves[_bondingCurve], "Bonding curve not whitelisted");

120:          require(shareIDs[_shareName] == 0, "Share already exists");

151:          require(shareData[_id].creator != msg.sender, "Creator cannot buy");

254:          require(shareData[_id].creator == msg.sender, "Not creator");

301:          require(shareCreationRestricted != _isRestricted, "State already set");

310:          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");

```


*GitHub* : [81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L81-L84),[105](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L105),[119](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L119),[120](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L120),[151](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L151),[254](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L254),[301](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L301),[310](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L310)

```solidity
File: src/asD.sol

54:           require(returnCode == 0, "Error when minting");

81:               require(_amount <= maximumWithdrawable, "Too many tokens requested");

```


*GitHub* : [54](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L54),[81](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L81)
### [D&#x2011;12] ~~Duplicated require()/revert() checks should be refactored to a modifier Or function to save gas~~
If the compiler inlines the function, there will be no gas savings. If it doesn't, there's extra runtime overhead due to the JUMP instructions. Either way, this suggestion is not helpful.

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

86:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86)
### [D&#x2011;13] ~~Enable IR-based code generation~~
By using `--via-ir` or `{"viaIR": true}`, the compiler is able to use more advanced [multi-function optimizations](https://docs.soliditylang.org/en/v0.8.17/ir-breaking-changes.html#solidity-ir-based-codegen-changes), for extra gas savings.

*There are 1 instance(s) of this issue:*

```solidity
File: Various Files


```


*GitHub* : [various](https://github.com/code-423n4/2023-11-canto/tree/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts)
### [D&#x2011;14] ~~Event names should use CamelCase~~
The instances below are already CamelCase (events are supposed to use CamelCase, not lowerCamelCase)

*There are 12 instance(s) of this issue:*

```solidity
File: src/Market.sol

69:      event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

70:      event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);

71:      event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);

72:      event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);

73:      event NFTsCreated(uint256 indexed id, address indexed creator, uint256 amount, uint256 fee);

74:      event NFTsBurned(uint256 indexed id, address indexed burner, uint256 amount, uint256 fee);

75:      event PlatformFeeClaimed(address indexed claimer, uint256 amount);

76:      event CreatorFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

77:      event HolderFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

78:      event ShareCreationRestricted(bool isRestricted);

```


*GitHub* : [69](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L69-L69),[70](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L70-L70),[71](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L71-L71),[72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L72-L72),[73](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L73-L73),[74](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L74-L74),[75](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L75-L75),[76](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L76-L76),[77](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L77-L77),[78](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L78-L78)

```solidity
File: src/asD.sol

20:      event CarryWithdrawal(uint256 amount);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L20-L20)

```solidity
File: src/asDFactory.sol

20:      event CreatedToken(address token, string symbol, string name, address creator);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L20-L20)
### [D&#x2011;15] ~~Events that mark critical parameter changes should contain both the old and the new value~~
These are not critical parameter changes

*There are 11 instance(s) of this issue:*

```solidity
File: src/Market.sol

126:         emit ShareCreated(id, _shareName, _bondingCurve, msg.sender);

168:         emit SharesBought(_id, msg.sender, _amount, price, fee);

188:         emit SharesSold(_id, msg.sender, _amount, price, fee);

220:         emit NFTsCreated(_id, msg.sender, _amount, fee);

240:         emit NFTsBurned(_id, msg.sender, _amount, fee);

248:         emit PlatformFeeClaimed(msg.sender, amount);

258:         emit CreatorFeeClaimed(msg.sender, _id, amount);

269:         emit HolderFeeClaimed(msg.sender, _id, amount);

303:         emit ShareCreationRestricted(_isRestricted);

```


*GitHub* : [126](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L126-L126),[168](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L168-L168),[188](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L188-L188),[220](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L220-L220),[240](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L240-L240),[248](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L248-L248),[258](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L258-L258),[269](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L269-L269),[303](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L303-L303)

```solidity
File: src/asD.sol

89:          emit CarryWithdrawal(_amount);

```


*GitHub* : [89](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L89-L89)

```solidity
File: src/asDFactory.sol

36:          emit CreatedToken(address(createdToken), _symbol, _name, msg.sender);

```


*GitHub* : [36](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L36-L36)
### [D&#x2011;16] ~~Inconsistent comment spacing~~
URLs are not comments

*There are 4 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

41:       /// @notice Copied from Solady: https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol

```


*GitHub* : [41](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L41)

```solidity
File: src/asD.sol

53:           // Mint returns 0 on success: https://docs.compound.finance/v2/ctokens/#mint

64:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem-underlying

86:           require(returnCode == 0, "Error when redeeming"); // 0 on success: https://docs.compound.finance/v2/ctokens/#redeem

```


*GitHub* : [53](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L53),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L64),[86](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L86)
### [D&#x2011;17] ~~It is standard for all external and public functions to be override from an interface~~
According to the Solidity [docs](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding), "Starting from Solidity 0.8.8, the `override` keyword is not required when overriding an interface function, except for the case where the function is defined in multiple bases", so while it may have been a requirement in the past, they're trying to change that. Paired with the advice of making all `public` and `external` functions a part of an `interface`, this finding would end up having all sponsors mark all `public`/`external` functions with `override`, making the keyword meaningless. It's better to use `override` only when something is actually being overridden.

*There are 2 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

14       function getPriceAndFee(uint256 shareCount, uint256 amount)
15           external
16           view
17           override
18           returns (uint256 price, uint256 fee)
19:      {

27:      function getFee(uint256 shareCount) public pure override returns (uint256) {

```


*GitHub* : [14](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L14-L19),[27](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L27-L27)
### [D&#x2011;18] ~~It's not standard to end and begin a code object on the same line~~
These are perfectly standard

*There are 11 instance(s) of this issue:*

```solidity
File: src/Market.sol

4:   import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

7:   import {IBondingCurve} from "../interface/IBondingCurve.sol";

8:   import {Turnstile} from "../interface/Turnstile.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L4-L4),[7](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L7-L7),[8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L8-L8)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

4:   import {IBondingCurve} from "../../interface/IBondingCurve.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L4-L4)

```solidity
File: src/asD.sol

4:   import {Turnstile} from "../interface/Turnstile.sol";

5:   import {IasDFactory} from "../interface/IasDFactory.sol";

7:   import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

9:   import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L4-L4),[5](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L5-L5),[7](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L7-L7),[9](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L9-L9)

```solidity
File: src/asDFactory.sol

4:   import {Turnstile} from "../interface/Turnstile.sol";

5:   import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

6:   import {asD} from "./asD.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L4-L4),[5](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L5-L5),[6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L6-L6)
### [D&#x2011;19] ~~Large approvals may not work with some ERC20 tokens~~
These are not maximum approvals, or approvals that grow over time, so there is no broken behavior here

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

51:          SafeERC20.safeApprove(note, cNote, _amount);

```


*GitHub* : [51](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L51-L51)
### [D&#x2011;20] ~~Loss of precision~~
The general rule is valid, but the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit division by divisor
35:          return 1e17 / divisor;

```


*GitHub* : [35](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L35-L35)
### [D&#x2011;21] ~~Low level calls with Solidity before 0.8.14 result in an optimiser bug~~
This assembly block does not call `mstore()`, so it's not possible to hit the bug here even if there are small future changes, so this doesn't seem low severity.

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

44           assembly {
45               r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
46               r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
47               r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
48               r := or(r, shl(4, lt(0xffff, shr(r, x))))
49               r := or(r, shl(3, lt(0xff, shr(r, x))))
50               // forgefmt: disable-next-item
51               r := or(
52                   r,
53                   byte(
54                       and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
55                       0x0706060506020504060203020504030106050205030304010505030400000000
56                   )
57               )
58:          }

```


*GitHub* : [44](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L44-L58)
### [D&#x2011;22] ~~Missing checks for state variable assignments~~
The general rule is valid, but the instances below are invalid

*There are 5 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit _amount
161:         shareData[_id].tokenCount += _amount;

/// @audit _amount
162:         shareData[_id].tokensInCirculation += _amount;

/// @audit _amount
163:         tokensByAddress[_id][msg.sender] += _amount;

/// @audit _amount
234:         tokensByAddress[_id][msg.sender] += _amount;

/// @audit _amount
235:         shareData[_id].tokensInCirculation += _amount;

```


*GitHub* : [161](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L161-L161),[162](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L162-L162),[163](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L163-L163),[234](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L234-L234),[235](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L235-L235)
### [D&#x2011;23] ~~Missing event and or timelock for critical parameter change~~
These assignments are not missing events

*There are 6 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit bondingCurve
118      ) external onlyShareCreator returns (uint256 id) {
119          require(whitelistedBondingCurves[_bondingCurve], "Bonding curve not whitelisted");
120          require(shareIDs[_shareName] == 0, "Share already exists");
121          id = ++shareCount;
122          shareIDs[_shareName] = id;
123          shareData[id].bondingCurve = _bondingCurve;
124          shareData[id].creator = msg.sender;
125          shareData[id].metadataURI = _metadataURI;
126          emit ShareCreated(id, _shareName, _bondingCurve, msg.sender);
127:     }

/// @audit creator
119          require(whitelistedBondingCurves[_bondingCurve], "Bonding curve not whitelisted");
120          require(shareIDs[_shareName] == 0, "Share already exists");
121          id = ++shareCount;
122          shareIDs[_shareName] = id;
123          shareData[id].bondingCurve = _bondingCurve;
124          shareData[id].creator = msg.sender;
125          shareData[id].metadataURI = _metadataURI;
126          emit ShareCreated(id, _shareName, _bondingCurve, msg.sender);
127:     }

/// @audit metadataURI
120          require(shareIDs[_shareName] == 0, "Share already exists");
121          id = ++shareCount;
122          shareIDs[_shareName] = id;
123          shareData[id].bondingCurve = _bondingCurve;
124          shareData[id].creator = msg.sender;
125          shareData[id].metadataURI = _metadataURI;
126          emit ShareCreated(id, _shareName, _bondingCurve, msg.sender);
127:     }

/// @audit platformPool
243      /// @notice Withdraws the accrued platform fee
244      function claimPlatformFee() external onlyOwner {
245          uint256 amount = platformPool;
246          platformPool = 0;
247          SafeERC20.safeTransfer(token, msg.sender, amount);
248          emit PlatformFeeClaimed(msg.sender, amount);
249:     }

/// @audit shareCreatorPool
251      /// @notice Withdraws the accrued share creator fee
252      /// @param _id ID of the share
253      function claimCreatorFee(uint256 _id) external {
254          require(shareData[_id].creator == msg.sender, "Not creator");
255          uint256 amount = shareData[_id].shareCreatorPool;
256          shareData[_id].shareCreatorPool = 0;
257          SafeERC20.safeTransfer(token, msg.sender, amount);
258          emit CreatorFeeClaimed(msg.sender, _id, amount);
259:     }

/// @audit shareCreationRestricted
298      /// @notice Restricts or unrestricts share creation
299      /// @param _isRestricted True if restricted, false if not
300      function restrictShareCreation(bool _isRestricted) external onlyOwner {
301          require(shareCreationRestricted != _isRestricted, "State already set");
302          shareCreationRestricted = _isRestricted;
303          emit ShareCreationRestricted(_isRestricted);
304:     }

```


*GitHub* : [118](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L118-L127),[119](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L119-L127),[120](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L120-L127),[243](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L243-L249),[251](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L251-L259),[298](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L298-L304)
### [D&#x2011;24] ~~Must approve or increase allowance first~~
The bot is just flagging `transferFrom()` calls without a prior approval. Many projects require you to approve their contract before using it, so this suggestion is not helpful, and certainly is not 'Low' severity, since that's the design and no funds are lost. There is no way for the project to address this issue other than by requiring that the caller send the tokens themselves, which has its own risks.

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

153:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), price + fee);

206:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);

229:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);

```


*GitHub* : [153](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L153-L153),[206](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L206-L206),[229](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L229-L229)

```solidity
File: src/asD.sol

50:          SafeERC20.safeTransferFrom(note, msg.sender, address(this), _amount);

```


*GitHub* : [50](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L50-L50)
### [D&#x2011;25] ~~NatSpec: Function declarations should have `@notice` tags~~
The compiler interprets `///` or `/**` comments [as this tag](https://docs.soliditylang.org/en/latest/natspec-format.html#tags) if one wasn't explicitly provided

*There are 20 instance(s) of this issue:*

```solidity
File: src/Market.sol

91:      constructor(string memory _uri, address _paymentToken) ERC1155(_uri) Ownable() {

104:     function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {

114      function createNewShare(
115          string memory _shareName,
116          address _bondingCurve,
117          string memory _metadataURI
118:     ) external onlyShareCreator returns (uint256 id) {

132:     function getBuyPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {

141:     function getSellPrice(uint256 _id, uint256 _amount) public view returns (uint256 price, uint256 fee) {

150:     function buy(uint256 _id, uint256 _amount) external {

174:     function sell(uint256 _id, uint256 _amount) external {

194:     function getNFTMintingPrice(uint256 _id, uint256 _amount) public view returns (uint256 fee) {

203:     function mintNFT(uint256 _id, uint256 _amount) external {

226:     function burnNFT(uint256 _id, uint256 _amount) external {

244:     function claimPlatformFee() external onlyOwner {

253:     function claimCreatorFee(uint256 _id) external {

263:     function claimHolderFee(uint256 _id) external {

300:     function restrictShareCreation(bool _isRestricted) external onlyOwner {

309:     function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {

```


*GitHub* : [91](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L91-L91),[104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104-L104),[114](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L114-L118),[132](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L132-L132),[141](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L141-L141),[150](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L150-L150),[174](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L174-L174),[194](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L194-L194),[203](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L203-L203),[226](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L226-L226),[244](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L244-L244),[253](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L253-L253),[263](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L263-L263),[300](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L300-L300),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309-L309)

```solidity
File: src/asD.sol

28       constructor(
29           string memory _name,
30           string memory _symbol,
31           address _owner,
32           address _cNote,
33           address _csrRecipient
34:      ) ERC20(_name, _symbol) {

47:      function mint(uint256 _amount) external {

60:      function burn(uint256 _amount) external {

72:      function withdrawCarry(uint256 _amount) external onlyOwner {

```


*GitHub* : [28](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L28-L34),[47](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L47-L47),[60](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L60-L60),[72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L72-L72)

```solidity
File: src/asDFactory.sol

24:      constructor(address _cNote) {

```


*GitHub* : [24](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L24-L24)
### [D&#x2011;26] ~~Not using the named return variables anywhere in the function is confusing~~
The variable is in fact used, so the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit r
42:      function log2(uint256 x) internal pure returns (uint256 r) {

```


*GitHub* : [42](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L42-L42)
### [D&#x2011;27] ~~Re-org attack~~
No specific vulnerability has been outlined, other than the fact that block chains have re-orgs, and nothing is being cloned here.

*There are 1 instance(s) of this issue:*

```solidity
File: src/asDFactory.sol

34:          asD createdToken = new asD(_name, _symbol, msg.sender, cNote, owner());

```


*GitHub* : [34](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L34-L34)
### [D&#x2011;28] ~~Reduce gas usage by moving to Solidity 0.8.19 or later~~
Already >= 0.8.19

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

2:   pragma solidity 0.8.19;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L2-L2)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

2:   pragma solidity 0.8.19;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L2-L2)
### [D&#x2011;29] ~~Return values of transfer()/transferFrom() not checked~~
The examples below are for known contracts that revert if they fail, are for non-ERC20 contracts, or aren't the right function

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

35:          _transferOwnership(_owner);

```


*GitHub* : [35](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L35-L35)
### [D&#x2011;30] ~~Revert on transfer to the zero address~~
Forcing called tokens to not allow transfers to `address(0)` breaks composability if that token requires this functionality.

*There are 13 instance(s) of this issue:*

```solidity
File: src/Market.sol

153:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), price + fee);

166:             SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);

187:         SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim + price - fee);

206:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);

217:             SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);

229:         SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);

238:         SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);

247:         SafeERC20.safeTransfer(token, msg.sender, amount);

257:         SafeERC20.safeTransfer(token, msg.sender, amount);

267:             SafeERC20.safeTransfer(token, msg.sender, amount);

```


*GitHub* : [153](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L153-L153),[166](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L166-L166),[187](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L187-L187),[206](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L206-L206),[217](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L217-L217),[229](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L229-L229),[238](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L238-L238),[247](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L247-L247),[257](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L257-L257),[267](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L267-L267)

```solidity
File: src/asD.sol

50:          SafeERC20.safeTransferFrom(note, msg.sender, address(this), _amount);

66:          SafeERC20.safeTransfer(note, msg.sender, _amount);

88:          SafeERC20.safeTransfer(note, msg.sender, _amount);

```


*GitHub* : [50](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L50-L50),[66](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L66-L66),[88](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L88-L88)
### [D&#x2011;31] ~~safeMint should be used in place of mint~~
These are not ERC721.mint() calls

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

52:          uint256 returnCode = cNoteToken.mint(_amount);

```


*GitHub* : [52](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L52-L52)
### [D&#x2011;32] ~~Setters should prevent re-setting of the same value~~
The general rule is valid, but the instances below are invalid

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

104      function changeBondingCurveAllowed(address _bondingCurve, bool _newState) external onlyOwner {
105          require(whitelistedBondingCurves[_bondingCurve] != _newState, "State already set");
106          whitelistedBondingCurves[_bondingCurve] = _newState;
107          emit BondingCurveStateChange(_bondingCurve, _newState);
108:     }

309      function changeShareCreatorWhitelist(address _address, bool _isWhitelisted) external onlyOwner {
310          require(whitelistedShareCreators[_address] != _isWhitelisted, "State already set");
311          whitelistedShareCreators[_address] = _isWhitelisted;
312:     }

```


*GitHub* : [104](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L104-L108),[309](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L309-L312)
### [D&#x2011;33] ~~Solidity version 0.8.20 may not work on other chains due to `PUSH0`~~
The general rule is valid, but the instances below are invalid

*There are 2 instance(s) of this issue:*

```solidity
File: src/asD.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L2-L2)

```solidity
File: src/asDFactory.sol

2:   pragma solidity >=0.8.0;

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2-L2)
### [D&#x2011;34] ~~SPDX identifier should be the in the first line of a solidity file~~
It's already on the first line

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

1:    // SPDX-License-Identifier: GPL-3.0-only

```


*GitHub* : [1](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L1)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

1:    // SPDX-License-Identifier: GPL-3.0-only

```


*GitHub* : [1](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L1)

```solidity
File: src/asD.sol

1:    // SPDX-License-Identifier: GPL-3.0-only

```


*GitHub* : [1](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L1)

```solidity
File: src/asDFactory.sol

1:    // SPDX-License-Identifier: GPL-3.0-only

```


*GitHub* : [1](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L1)
### [D&#x2011;35] ~~State variable read in a loop~~
These references to the variable cannot be cached, or the variable is `constant`/`immutable`

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit priceIncrease
21:              uint256 tokenPrice = priceIncrease * i;

```


*GitHub* : [21](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L21-L21)
### [D&#x2011;36] ~~Storage Write Removal Bug On Conditional Early Termination~~
In solidity versions 0.8.13 through 0.8.16, there is a [bug](https://blog.soliditylang.org/2022/09/08/storage-write-removal-before-conditional-termination/) involving the use of the Yul functions `return()` and `stop()`. If those functions aren't called, or if the Solidity version doesn't match, the finding is not low severity.

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

44           assembly {
45               r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
46               r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
47               r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
48               r := or(r, shl(4, lt(0xffff, shr(r, x))))
49               r := or(r, shl(3, lt(0xff, shr(r, x))))
50               // forgefmt: disable-next-item
51               r := or(
52                   r,
53                   byte(
54                       and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
55                       0x0706060506020504060203020504030106050205030304010505030400000000
56                   )
57               )
58:          }

```


*GitHub* : [44](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L44-L58)
### [D&#x2011;37] ~~Style guide: Contract does not follow the Solidity style guide's suggested layout ordering~~
There are no issues with contract layout in these contracts

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

10:   contract Market is ERC1155, Ownable2Step {

```


*GitHub* : [10](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L10)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

6:    contract LinearBondingCurve is IBondingCurve {

```


*GitHub* : [6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L6)

```solidity
File: src/asD.sol

11:   contract asD is ERC20, Ownable2Step {

```


*GitHub* : [11](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L11)

```solidity
File: src/asDFactory.sol

8:    contract asDFactory is Ownable2Step {

```


*GitHub* : [8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L8)
### [D&#x2011;38] ~~Style guide: Function Names Not in mixedCase~~
According to the Solidity Style Guide, non-`external`/`public` function names should begin with an [underscore](https://docs.soliditylang.org/en/latest/style-guide.html#underscore-prefix-for-non-external-functions-and-variables), and all of these fall into that category

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

272:     function _getRewardsSinceLastClaim(uint256 _id) internal view returns (uint256 amount) {

280      function _splitFees(
281          uint256 _id,
282          uint256 _fee,
283          uint256 _tokenCount
284:     ) internal {

```


*GitHub* : [272](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L272-L272),[280](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L280-L284)
### [D&#x2011;39] ~~Style guide: Function names should use lowerCamelCase~~
The general rule is valid, but the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

194:     function getNFTMintingPrice(uint256 _id, uint256 _amount) public view returns (uint256 fee) {

```


*GitHub* : [194](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L194-L194)
### [D&#x2011;40] ~~Tokens may be minted to `address(0x0)`~~
In the cases below, `_mint()` prevents minting to `address(0x0)`

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

203      function mintNFT(uint256 _id, uint256 _amount) external {
204          uint256 fee = getNFTMintingPrice(_id, _amount);
205  
206          SafeERC20.safeTransferFrom(token, msg.sender, address(this), fee);
207          _splitFees(_id, fee, shareData[_id].tokensInCirculation);
208          // The user also gets the proportional rewards for the minting
209          uint256 rewardsSinceLastClaim = _getRewardsSinceLastClaim(_id);
210          rewardsLastClaimedValue[_id][msg.sender] = shareData[_id].shareHolderRewardsPerTokenScaled;
211          tokensByAddress[_id][msg.sender] -= _amount;
212          shareData[_id].tokensInCirculation -= _amount;
213  
214          _mint(msg.sender, _id, _amount, "");
215  
216          if (rewardsSinceLastClaim > 0) {
217              SafeERC20.safeTransfer(token, msg.sender, rewardsSinceLastClaim);
218          }
219          // ERC1155 already logs, but we add this to have the price information
220          emit NFTsCreated(_id, msg.sender, _amount, fee);
221:     }

```


*GitHub* : [203](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L203-L221)
### [D&#x2011;41] ~~Top level pragma declarations should be separated by two blank lines~~
Pragmas aren't top-level declarations, and the [style guide](https://docs.soliditylang.org/en/latest/style-guide.html#blank-lines) doesn't use two spaces there.

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

2    pragma solidity 0.8.19;
3    
4:   import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L2-L4)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

2    pragma solidity 0.8.19;
3    
4:   import {IBondingCurve} from "../../interface/IBondingCurve.sol";

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L2-L4)

```solidity
File: src/asD.sol

2    pragma solidity >=0.8.0;
3    
4:   import {Turnstile} from "../interface/Turnstile.sol";

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L2-L4)

```solidity
File: src/asDFactory.sol

2    pragma solidity >=0.8.0;
3    
4:   import {Turnstile} from "../interface/Turnstile.sol";

```


*GitHub* : [2](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L2-L4)
### [D&#x2011;42] ~~Top-level declarations should be separated by at least two lines~~
The Style Guide [says](https://docs.soliditylang.org/en/v0.8.20/style-guide.html#blank-lines) that _functions_ should be separated by one line, not two

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

270       }
271   
272:      function _getRewardsSinceLastClaim(uint256 _id) internal view returns (uint256 amount) {

```


*GitHub* : [270](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L270-L272)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

12        }
13    
14:       function getPriceAndFee(uint256 shareCount, uint256 amount)

25        }
26    
27:       function getFee(uint256 shareCount) public pure override returns (uint256) {

```


*GitHub* : [12](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L12-L14),[25](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L25-L27)

```solidity
File: src/asDFactory.sol

31        }
32    
33:       function create(string memory _name, string memory _symbol) external returns (address) {

```


*GitHub* : [31](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L31-L33)
### [D&#x2011;43] ~~Trade-offs Between Modifiers and Internal Functions~~
There is nothing that the sponsor can do that would make this finding disappear, besides never using modifiers, so it's not a useful finding.

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

118:     ) external onlyShareCreator returns (uint256 id) {

```


*GitHub* : [118](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L118-L118)
### [D&#x2011;44] ~~Unnecessary look up in if condition~~

*There are 5 instance(s) of this issue:*

```solidity
File: src/Market.sol

82:              !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),

82:              !shareCreationRestricted || whitelistedShareCreators[msg.sender] || msg.sender == owner(),

93:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [82](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L82-L82),[82](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L82-L82),[93](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L93-L93)

```solidity
File: src/asD.sol

37:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [37](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L37-L37)

```solidity
File: src/asDFactory.sol

26:          if (block.chainid == 7700 || block.chainid == 7701) {

```


*GitHub* : [26](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L26-L26)
### [D&#x2011;45] ~~Unused function parameter~~
The variable is in fact used, so the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit x
42:      function log2(uint256 x) internal pure returns (uint256 r) {

```


*GitHub* : [42](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L42-L42)
### [D&#x2011;46] ~~Unused import~~
These instances _are_ used

*There are 18 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit ERC1155
4:   import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

/// @audit SafeERC20
/// @audit IERC20
5:   import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @audit Ownable
/// @audit Ownable2Step
6:   import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @audit IBondingCurve
7:   import {IBondingCurve} from "../interface/IBondingCurve.sol";

/// @audit Turnstile
8:   import {Turnstile} from "../interface/Turnstile.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L4-L4),[5](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L5-L5),[5](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L5-L5),[6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L6-L6),[6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L6-L6),[7](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L7-L7),[8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L8-L8)

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

/// @audit IBondingCurve
4:   import {IBondingCurve} from "../../interface/IBondingCurve.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L4-L4)

```solidity
File: src/asD.sol

/// @audit Turnstile
4:   import {Turnstile} from "../interface/Turnstile.sol";

/// @audit CTokenInterface
/// @audit CErc20Interface
6:   import {CTokenInterface, CErc20Interface} from "../interface/clm/CTokenInterfaces.sol";

/// @audit Ownable2Step
7:   import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @audit IERC20
/// @audit ERC20
8:   import {IERC20, ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @audit SafeERC20
9:   import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L4-L4),[6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L6-L6),[6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L6-L6),[7](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L7-L7),[8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L8-L8),[8](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L8-L8),[9](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L9-L9)

```solidity
File: src/asDFactory.sol

/// @audit Turnstile
4:   import {Turnstile} from "../interface/Turnstile.sol";

/// @audit Ownable2Step
5:   import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @audit asD
6:   import {asD} from "./asD.sol";

```


*GitHub* : [4](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L4-L4),[5](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L5-L5),[6](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L6-L6)
### [D&#x2011;47] ~~Unusual loop variable~~
These instances all properly use 'i' as the outer for-loop loop variable

*There are 1 instance(s) of this issue:*

```solidity
File: src/bonding_curve/LinearBondingCurve.sol

20:          for (uint256 i = shareCount; i < shareCount + amount; i++) {

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/bonding_curve/LinearBondingCurve.sol#L20-L20)
### [D&#x2011;48] ~~Use != 0 instead of > 0 for unsigned integer comparison~~
Only valid prior to Solidity version 0.8.13, and only for `require()` statements, and at least one of those is not true for the examples below

*There are 4 instance(s) of this issue:*

```solidity
File: src/Market.sol

165:         if (rewardsSinceLastClaim > 0) {

216:         if (rewardsSinceLastClaim > 0) {

266:         if (amount > 0) {

289:         if (_tokenCount > 0) {

```


*GitHub* : [165](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L165-L165),[216](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L216-L216),[266](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L266-L266),[289](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L289-L289)
### [D&#x2011;49] ~~Use `_safeMint` instead of `_mint` for ERC721~~
The contract here isn't an ERC721 - it's some other token. Note that ERC1155 defines `_mint()`, not `_safeMint()`

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

194:     function getNFTMintingPrice(uint256 _id, uint256 _amount) public view returns (uint256 fee) {

203:     function mintNFT(uint256 _id, uint256 _amount) external {

```


*GitHub* : [194](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L194-L194),[203](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L203-L203)

```solidity
File: src/asD.sol

47:      function mint(uint256 _amount) external {

```


*GitHub* : [47](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L47-L47)
### [D&#x2011;50] ~~Use `assembly` to write address/contract type storage values~~
Using this suggestion stomps over any value packed into the same slot as the address, so this advice is not generically safe.

*There are 5 instance(s) of this issue:*

```solidity
File: src/Market.sol

92:          token = IERC20(_paymentToken);

123:         shareData[id].bondingCurve = _bondingCurve;

124:         shareData[id].creator = msg.sender;

```


*GitHub* : [92](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L92-L92),[123](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L123-L123),[124](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L124-L124)

```solidity
File: src/asD.sol

36:          cNote = _cNote;

```


*GitHub* : [36](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L36-L36)

```solidity
File: src/asDFactory.sol

25:          cNote = _cNote;

```


*GitHub* : [25](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L25-L25)
### [D&#x2011;51] ~~Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes~~
These are never reset to `false`, so there is no gas savings in making the change

*There are 1 instance(s) of this issue:*

```solidity
File: src/asDFactory.sol

15:      mapping(address => bool) public isAsD;

```


*GitHub* : [15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L15-L15)
### [D&#x2011;52] ~~Use assembly to emit events, in order to save gas~~
For these events, there doesn't appear to be more than [one word's worth](https://gist.github.com/IllIllI000/07f18824f5061a5f265785607dc88f55) of unindexed args, or the arguments are too large to fit in the scratch space, so findings related to these events are likey invalid and definitely invalid, respectively.

*There are 10 instance(s) of this issue:*

```solidity
File: src/Market.sol

69:      event BondingCurveStateChange(address indexed curve, bool isWhitelisted);

70:      event ShareCreated(uint256 indexed id, string name, address indexed bondingCurve, address indexed creator);

71:      event SharesBought(uint256 indexed id, address indexed buyer, uint256 amount, uint256 price, uint256 fee);

72:      event SharesSold(uint256 indexed id, address indexed seller, uint256 amount, uint256 price, uint256 fee);

75:      event PlatformFeeClaimed(address indexed claimer, uint256 amount);

76:      event CreatorFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

77:      event HolderFeeClaimed(address indexed claimer, uint256 indexed id, uint256 amount);

78:      event ShareCreationRestricted(bool isRestricted);

```


*GitHub* : [69](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L69-L69),[70](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L70-L70),[71](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L71-L71),[72](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L72-L72),[75](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L75-L75),[76](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L76-L76),[77](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L77-L77),[78](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L78-L78)

```solidity
File: src/asD.sol

20:      event CarryWithdrawal(uint256 amount);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L20-L20)

```solidity
File: src/asDFactory.sol

20:      event CreatedToken(address token, string symbol, string name, address creator);

```


*GitHub* : [20](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L20-L20)
### [D&#x2011;53] ~~Use delete instead of setting mapping/state variable to zero, to save gas~~
Using delete instead of assigning zero to state variables does not save any extra gas with the optimizer [on](https://gist.github.com/IllIllI000/ef8ec3a70aede7f12433fe63dc418515#with-the-optimizer-set-at-200-runs) (saves 5-8 gas with optimizer completely off), so this finding is invalid, especially since if they were interested in gas savings, they'd have the optimizer enabled.

*There are 2 instance(s) of this issue:*

```solidity
File: src/Market.sol

246:         platformPool = 0;

256:         shareData[_id].shareCreatorPool = 0;

```


*GitHub* : [246](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L246-L246),[256](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L256-L256)
### [D&#x2011;54] ~~Use of a single-step ownership transfer~~
There is no prior owner here

*There are 1 instance(s) of this issue:*

```solidity
File: src/asD.sol

28       constructor(
29           string memory _name,
30           string memory _symbol,
31           address _owner,
32           address _cNote,
33           address _csrRecipient
34       ) ERC20(_name, _symbol) {
35           _transferOwnership(_owner);
36           cNote = _cNote;
37           if (block.chainid == 7700 || block.chainid == 7701) {
38               // Register CSR on Canto main- and testnet
39               Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);
40               turnstile.register(_csrRecipient);
41           }
42:      }

```


*GitHub* : [28](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asD.sol#L28-L42)
### [D&#x2011;55] ~~Using `calldata` instead of `memory` for read-only arguments in `public`/`external` functions saves gas~~
The function argument is not read-only

*There are 1 instance(s) of this issue:*

```solidity
File: src/Market.sol

/// @audit createNewShare(_shareName)
122:         shareIDs[_shareName] = id;

```


*GitHub* : [122](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L122-L122)
### [D&#x2011;56] ~~Using bitmap to store bool states can save gas~~
none of these are examples where bitmaps can be used

*There are 3 instance(s) of this issue:*

```solidity
File: src/Market.sol

49:      mapping(address => bool) public whitelistedBondingCurves;

64:      mapping(address => bool) public whitelistedShareCreators;

```


*GitHub* : [49](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L49-L49),[64](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/1155tech-contracts/src/Market.sol#L64-L64)

```solidity
File: src/asDFactory.sol

15:      mapping(address => bool) public isAsD;

```


*GitHub* : [15](https://github.com/code-423n4/2023-11-canto/blob/516099801101950ac9e1117a70e095b06f9bf6a1/asD/src/asDFactory.sol#L15-L15) ## Rubric
See [this](https://illilli000.github.io/races/2023-07-lens/scorer.html) link for how to use this rubric:
```json
{"salt":"cc29e6","hashes":["3a0cf33300","8f7762eff7","a3df9da1d8","429207439d","87b9a9ed5d","a520d4e935","3956d0c4a2","8e29c35cb6","c041709eac","3136f47a73","a88e0ddf1b","1ee55a2d3f","8fb8bf3e08","4cef8a270a","92acf34c16","52ae62048d","3510b63838","ed5910d288","0e49ede49c","99662e2be9","a8a8cf2f0a","99447ba456","d999ebd0ad","d14cd32d4e","2cfd062320","100ffcde30","fd150a5131","9dfe7a9522","26653e4597","b8907954b1","e2797d4d79","b592958615","694c482fb4","f63f774e8d","79e34e9bb6","dae5c0b3be","b991d26592","a3ff17e80f","33c8ed242b","923d35371c","0d9ab7e87b","c49a780361","9e43cfd365","70445ffc92","7736b63a1a","e2c19fd7f8","2f148160d7","e213e58022","c2fd1f33db","8c5beb1900","af0e3b4468","2b873c26de","f968bcb74a","8c9c82c5bb","4d6703bfe9","0ef7ffde65","cb0ca85660","0bfae4de15","3b23d97ed8","fb01cae23d","2618fed14d","bc82db90d7","92b2ab4964","ab674a7c6e","b32a327486","f912652701","99bfc29347","285469f6cd","7c909d79f7","e563ee440d","3bc7f8eca4","0367f90eb6","b6a5bc270b","0bfcae0b83","b0296fb183","64dec7e384","7aa2e70fc0","dae5c0b3be","b991d26592","a3ff17e80f","33c8ed242b","923d35371c","0d9ab7e87b","c49a780361","dae5c0b3be","b991d26592","a3ff17e80f","33c8ed242b","923d35371c","0d9ab7e87b","c49a780361","866c7c63df","208a7653a6","7a47bb3bbd","07397c4db0","3ee0bea812","df3215ec76","ce67cc9aa1","dcadc4ce3e","bcece945f9","c705856a07","069bcfd9ba","6c9119ae2b","36f1ce8639","cc6209c26b","3cd8a643f0","45ee78bc99","eb6d2afd73","4e0e91b984","f2aa3f2153","8f47774410","dd2d245440","3cd8a643f0","45ee78bc99","eb6d2afd73","4e0e91b984","f2aa3f2153","8f47774410","dd2d245440","93084eaad6","6aa7ab342d","7b1db947a4","f81b985aac","5391a2bd84","148b3ce6c0","63ba0c2348","89abe712cf","63669c2e39","48f6c19a93","5aaa9e92ef","db71848f5e","956d446059","4d16da1af6","ac8f6395a5","81ed02fa34","ce3cd4ddf5","e2dc8f15ae","2eb3057f0f","c3c23f8c17","a41e012283","ac8f6395a5","81ed02fa34","ce3cd4ddf5","e2dc8f15ae","2eb3057f0f","c3c23f8c17","a41e012283","69aa2823b0","35ff435c56","9a93608d20","a238cebe9d","96d0369653","676cacb6e1","33b0f2ce52","93721dab59","be77797d8a","9af6b05c99","35dfebff46","c670c60248","171834b310","3c6eac62ea","578bb23558","82f4e22312","446d283817","b31d41da6c","71efdc10e0","1ce9e696dc","6c941e46d3","796b19341f","21df0194de","9cca3af49d","a2148c1d4a","441d3eb82c","99c2078e06","20b4eb3ab6","d3b5d02546","f078740eee","a2d73d8016","1e5642d008","f44f3fd8ea","06d88298b1","ef2c301558","658d1da77d","b4dc1023aa","050066ea1f","a7d4891256","f346bc5389","b05d941832","a72bbe7b9d","69aa2823b0","35ff435c56","9a93608d20","a238cebe9d","96d0369653","676cacb6e1","33b0f2ce52","7786582965","3445c626dd","8d90554f64","6a536df419","f3549b5d17","a3491cef01","702c05cdf9","8a9fa82444","166b1e6521","aeee124509","70445b8fe3","abfc5ea88b","955f9dcb6e","3ed09d399b","cf029cb2cb","f1d6eb2afa","873e5d43ce","62b6fc2bcc","46902272ef","9eddba2e41","437520bc5d","cf029cb2cb","f1d6eb2afa","873e5d43ce","62b6fc2bcc","46902272ef","9eddba2e41","437520bc5d","3e54f4e62f","32bf5b18e8","509c856fd9","9f9ae2c4a3","6569bdbd9d","aecf2d7bbd","f9a63efb53","aee9d6ef0f","d7a335adb8","552fbb67f8","e968187439","e75e60b68f","8b1d8458d4","63acbde974","992074437b","86a5222b1c","2bd7d73d70","c25379f1b9","c99535539b","a68658b9cc","95ec87552c","a6240ee4ca","1db18a1312","20e19abf26","c8bacbd7fb","608067f389","00a403d1cd","ece03d24c4","bad62b7e83","79c39d4212","3cf351f61a","2b7b5bd8ce","11f2c2f975","c30d822b69","061f1441d3","1688b66207","ef12afb1ab","eeebfdde46","36678a2918","dbe84f6742","d1c1dbd976","4ee9db607a","38d351513b","b9b8b676ac","b13a7085c0","234e13c057","2ea5def886","14fd5e2346","cd0df90614","3e54f4e62f","32bf5b18e8","509c856fd9","9f9ae2c4a3","6569bdbd9d","aecf2d7bbd","f9a63efb53","b64aaa1138","7dc84e4ca5","70764fecba","c720f95d9c","2028f1e882","86f4df6342","325846a6be","d25f9d2af6","eeb8ccde8c","7f5d6629b1","9192c68337","1f274032a9","60440705af","0526dbdf5c","9844f99e56","cf424acfdd","1d06614e9c","37aa79e75d","704d4c3eb3","bc41770252","024de501aa","92d3dea622","173c495355","c1a1f083af","eaa86c668c","e5cad55827","190009ebac","d3fe1edd48","d25caa595c","07beb8d5af","748006c339","64417469ef","c8826fe332","fa0273a8a8","c061b76d09","d5a6aa6d36","bce8da0897","12ca827b9c","fb8b930f15","613c8773a8","0020fdb3be","a577b88ae8","7ffb3ba9a4","81901d2aad","437b63d854","b5a8f7ca04","a6ef3b3f00","e65802994b","b8c0044e87","3c8c23d0e9","38a9229784","5238df30cb","e2d58fcbf7","d7c285baee","bb04539f50","95ddc5b9e5","4923c08dbe","804453cc7c","6d65d5f619","c24dc46078","e786fda565","015958376d","7b2899a60f","163494446b","d3800baea8","0ea37f1976","24abfe1662","524f76ded3","719306d893","2edc7b23dc","b1cc111ba1","cbf6237271","9926c534b1","e656a2f6d5","cae9d60256","02156bdf26","2702489775","d25caa595c","07beb8d5af","748006c339","64417469ef","c8826fe332","fa0273a8a8","c061b76d09","ec29e7c6f9","7e5c8fa354","b88321e78f","91c154b9da","d9ae9e53cd","a618b51391","e068cdd586","c92a28c97a","b22d5a64d9","2be98367be","63778edf43","1b12afc44b","5e87663880","171f49ef7e","d5feb12a0c","3a0402eb37","e5a5f204f3","02c864ea7d","d75b7700f3","b9040e7fc0","21988ab453","ccc9a83afc","260db7bbf9","1aeefdc3ab","09f2814570","f825aae499","1dcbd343f2","cade2c74fb","d25caa595c","07beb8d5af","748006c339","64417469ef","c8826fe332","fa0273a8a8","c061b76d09","b01360438e","67b5d6b96d","7ee67197c5","e46c11d4eb","9ee5367d7f","a0ce30eb68","cf808ed536","1e83fa03d7","45e50bf194","e549bc6ebd","88333dc004","1cefd77a50","795fbb91db","da35e07683","715814d739","8cf056fdd0","aec9b6dbec","ff9d5d764d","e7ef429701","b3dbe69620","6f7f9c1fdf","af557e4c43","4441a54dec","5114167d5f","520a73c37f","3f571e7649","f46c64eabe","28e9bb3329","798a38b7b7","562e4b7b9f","5867cff9ed","4b7c1d32fc","d74e17fb1b","de39062c95","6c5fd68f14","b100e6aaad","45d96d285b","acafd6ee6f","c26af8f5aa","ebb636f039","7097cd1100","2c5afe78d0","78ca3e4c97","8f47867c28","2b28b6f1a4","a4f66178e9","8b7f23d735","f87ee348de","e8a3089f90","b4493213eb","122c3f464f","a0906fee12","fb557f6eb8","faaec7f10f","d5e0adcbaa","4f79af416a","3cbf7a370f","2a110d41a3","9bb7784364","a8f5cc8b14","13b440c94a","8b67820bfb","3dc14c5aff","1f0ec0f8e7","60dbdffbe2","f11052096d","32760894de","b9c6095076","58b5f1da41","ef5cc5b87e","1ff8741d0e","6f0d969bde","1d4a64f537","ffce404492","5fe6c8fb36","c8191407de","597f700692","2937043d0f","27ea177558","233c4fe379","3dac17b52d","f779ea43f5","92a9fb7007","46f3586f2d","d94467c118","6b3c6767c4","abfb67f526","485e12b1d8","3932b3333f","fbc4928c84","7ecf898326","48aaac3530","91c0365185","b2b9144255","a36be67da9","80d66dadaa","142361e224","2f9535dfd1","4d7ddb04bb","9997fe390a","fd2f81cb62","b107af74fd","5501807c13","30c11d4c23","d38480a582","af557e4c43","4441a54dec","5114167d5f","520a73c37f","3f571e7649","f46c64eabe","28e9bb3329","78ca3e4c97","8f47867c28","2b28b6f1a4","a4f66178e9","8b7f23d735","f87ee348de","e8a3089f90","78ca3e4c97","8f47867c28","2b28b6f1a4","a4f66178e9","8b7f23d735","f87ee348de","e8a3089f90","7badebf07e","4ab5a35733","07713d8980","12e130c817","caa8f4d22a","ab875d6723","dec66169ab","7badebf07e","4ab5a35733","07713d8980","12e130c817","caa8f4d22a","ab875d6723","dec66169ab","22c0bc5fd5","ff5f76930c","5330dcaf5c","b0d2b766f2","4f3da1a5a3","f142664a79","5fcfe5a7e4","64e8fd56b3","a99fcdaa85","c93a6886da","b7cae83abd","32f5f748cc","ee8b3a9ae9","a71e0114af","7faa20ddee","3589ce1ef4","1cd183f6a6","be8efad4bb","0302bf3cf2","3381e226f0","325f9fab6e","de4a7e8e87","cfd19e8433","e9bdb33c38","46796d6821","b6602dbcfe","aa51b9398b","aa0b5cba63","c502f44967","c0abb90a15","ce8b9192c3","8544056fd8","c438d657f1","f83c226d45","98a791fbd8","66a68183b0","3b4a34f832","522d0e5e93","2e843f67ef","01910c0eaf","97a29721b3","e7cf2c85a9","707a3c23bf","3499fb0700","6a77a50a5c","cb17e733bd","71c579d365","c84d65c123","d6e1bc3e25","64e8fd56b3","a99fcdaa85","c93a6886da","b7cae83abd","32f5f748cc","ee8b3a9ae9","a71e0114af","707a3c23bf","3499fb0700","6a77a50a5c","cb17e733bd","71c579d365","c84d65c123","d6e1bc3e25","707a3c23bf","3499fb0700","6a77a50a5c","cb17e733bd","71c579d365","c84d65c123","d6e1bc3e25","30ca272012","f9a794d184","e04e1310bd","ceafb816d4","19dc052767","8ab10cedb0","5fa63a1ecf","f7402c5a29","8d9ca90ec6","20ea578146","087996c18b","57728c7b2c","0c5aa94fb8","1863925226","1885469eda","09e1fadeba","a73e99582c","1e6588c26b","268d10a2df","0b5976fb96","1436abaf7e","7457839224","a0d2c58645","c45f30a212","cf358dceb7","f924c80f49","38d8a167fb","84b7b4ec42","1885469eda","09e1fadeba","a73e99582c","1e6588c26b","268d10a2df","0b5976fb96","1436abaf7e","f7402c5a29","8d9ca90ec6","20ea578146","087996c18b","57728c7b2c","0c5aa94fb8","1863925226","907e892eea","3d933640d2","7f3cc361c1","8c47fe2c4b","d265ea8b80","41a511a305","a0838dfe24","d68787fe83","58c8766e29","24eadc74f8","e5aaf61ba1","6d1b7ace30","3a705fb7a6","fd231659f1","f7402c5a29","8d9ca90ec6","20ea578146","087996c18b","57728c7b2c","0c5aa94fb8","1863925226","f7402c5a29","8d9ca90ec6","20ea578146","087996c18b","57728c7b2c","0c5aa94fb8","1863925226","60c05a707e","46d21e560c","42cb3f54d0","f9e7bb3401","e062c72d16","4c3786908d","f67e197591","dd3257dfb4","f8878c0dea","0be5cb8fbc","6b0db2a2f6","cb37269c1a","09b0e6a19c","83fb700899","65d6ffc225","a1e448b4e7","4dd55ba878","3d92c983ce","73bd984bf7","41298fd63e","b91d09f49e","d2d0809d90","af5c173355","dbaf6f7729","79cd860467","ff190ae0cd","b771f06901","cdc7de63df","65d6ffc225","a1e448b4e7","4dd55ba878","3d92c983ce","73bd984bf7","41298fd63e","b91d09f49e","22de23db6c","b0e006e428","67e6b114ee","a6b7b0308b","4a4c65ada0","d0d62f1ac9","55b2b1e7ad","295e760f4d","bd79f60ad4","b3dbbc2dfd","2c4f0d8d0f","3f79d1909c","e7989f6860","6adfdf1936","295e760f4d","bd79f60ad4","b3dbbc2dfd","2c4f0d8d0f","3f79d1909c","e7989f6860","6adfdf1936","0ad1e86e27","b4a23225fa","78f438be50","bc25073b43","e58ba796b3","5797123a20","20efdbe155","30da3361b0","007fa839f2","ac8f1c0458","7973114ffc","ebd14c388c","cb2aec8801","834dd5fddb","548b84e251","a8b9f55c7f","b028872b61","71e4f7bbe5","b97b01b20a","f5718456a2","1839c56d88","a94d5e50de","ebdab5d3bd","eefbe8fd21","263fa9afe3","00f09ff553","0a8cfc6ca0","2bcfff7897","f86fb2f3b6","1c26b9beeb","33f20d60ae","f41549dfce","98b982384d","d045d69b1e","aee9879a35","94c14b1d7a","ab766e115e","b60f297432","0bb65b3215","468ac77786","f14adab452","6273144b5c","2a6d42d379","e67e799f22","964d006024","d73e56f4d7","1b0411aaa2","8c212d4b31","1e1252bef6","2a6d42d379","e67e799f22","964d006024","d73e56f4d7","1b0411aaa2","8c212d4b31","1e1252bef6","2429797fa1","2a8d6f098d","93ed9f1752","b6b7ae128b","15c56bd5e4","485ed6665b","f7312472fe","1c4ff70d07","ca3c1a5f55","6a0b3f8923","0c10e8b075","99b3a308e5","c94d95d636","c1c00faafe","d146e8f121","c1dc350fad","2fa52c6434","dad5e71563","cfffeb2500","87c79d4ed3","d3e7ed861b","d146e8f121","c1dc350fad","2fa52c6434","dad5e71563","cfffeb2500","87c79d4ed3","d3e7ed861b","463ef010df","6398c62c62","45291d0fe7","3451acbc8c","eef0939f58","ab64de6f57","c375d8a11f","a153476012","8a64125df1","9be68d4aac","6f35f4e471","ef8a4443c3","134d3b7eec","9987103554","3233ab7e03","9b14834b6a","5c41979216","4546389fcf","cbae908acc","15734b83ca","a32608f281","97ea8fd3ba","445e3ffe1d","73369e2b5d","278d9d97fc","b557d816ba","6585ba0062","19ce6c8435","5724697664","a345901a18","580310db6f","07d1a88eab","d8d2db5b2d","99bd5466bd","4c507d777d","331bbee0e9","50a7bbde61","7237e588b9","2f981deb1c","56ea77e984","81d19eb415","ab2ab87509","014ec75f86","6a85078d40","fe295bfca2","799cf9dc1e","1152f1317b","f6bccd9ea9","11b51de4e5","0a3bf562b8","c12d54a260","a71ac54a18","cd9da2b4c2","9b880d79dd","7992f53b9d","687ac07268","fe20a5d0b1","f545388e93","e2a15f7088","97062ff26a","9bad835b60","59d2d017b1","db51fd5e76","ad4c0f5268","4903346209","f06053f625","e45cd9d4d0","d9e6548723","d5b342d2a1","f7030e367b","3233ab7e03","9b14834b6a","5c41979216","4546389fcf","cbae908acc","15734b83ca","a32608f281","94cb24a684","b703e264a4","6904a9fa78","f8888b6bac","2076423eda","6f298c91a3","a1e1787019","e326aed68c","ae3d15564f","6b40f705e9","1acad77850","9625f81b89","8b2db2694e","7ca40dd236","612dc259f5","3a934e1872","1e4b34f52d","acf6ee4c9c","72305f8fe2","e34e079a39","cb8e5b553d","e326aed68c","ae3d15564f","6b40f705e9","1acad77850","9625f81b89","8b2db2694e","7ca40dd236","cf99195b81","3d6fe169cf","4d30bb266e","3e81b71fb1","052d1cb2a6","e52cd1a01b","cb5fb5d7aa","c4c8a369c5","e08c8deec4","e239324f27","15785dd5c7","b1fc398378","a08574fe46","34f05486f2","6d2e804bb0","27e2882685","f38002dd8d","153a88013f","2343d86c2d","0fa861909c","2c34c07761","b429ffdfed","f8e55c5481","6e1bc2eea7","49d9ab8846","19d03d1bef","1e1bdd10a0","27d522cd21","b429ffdfed","f8e55c5481","6e1bc2eea7","49d9ab8846","19d03d1bef","1e1bdd10a0","27d522cd21","ee93fbda38","0e59f34a48","7dfecb60a6","f82fd5e34e","047fe9d274","1eb66e2717","badbc6b2a3","5ddb714674","268ea5f1b5","91c52ee7de","dabe16a71e","fe195b5a86","563c522cc2","94e10bf590","d1a1b79510","d703b3e511","f0dce9d041","15848040ae","8fb25694b4","42e716febe","3fcbd224b4","4f295fb5dd","65590bc02f","cea4db9696","7b2f04aaf2","29905ee4a9","c3a4dea35f","555ca7c29c","d3a8a428d4","8c366e92e5","0b34068e96","2918d109b4","ab47917c3e","b6b8168c4e","7ae62f6198","d3a8a428d4","8c366e92e5","0b34068e96","2918d109b4","ab47917c3e","b6b8168c4e","7ae62f6198","906da42bea","f64c90f779","1930d5f152","c3d2e6f357","c0dfc9d007","976e4af85c","dbab11be68","f9fd86b1dd","2d8542d9f8","736e85fbb0","bb919a4086","8c06419c3d","61112cd369","3a5716d91c","f97f5c3017","536f252903","3f56c7f73b","533c4c3f92","a466008972","c19c6a6b18","cd3988cd59","48bce9635e","e7990abe4f","13f247f063","49141763a9","05c6180153","8d935f3646","4d863890ac","85b520fc30","3ffdad9ae3","02dd65f339","1b5af2d791","d1164121ab","fb4511ffc0","a9032a7fd1","85b520fc30","3ffdad9ae3","02dd65f339","1b5af2d791","d1164121ab","fb4511ffc0","a9032a7fd1","85b520fc30","3ffdad9ae3","02dd65f339","1b5af2d791","d1164121ab","fb4511ffc0","a9032a7fd1","4068a7b0d6","bf32e82353","45e4b506f3","a55477c3cf","c6ad33978d","fa8f1bd7fb","c560b3eee8","9309915ac9","f5de472b87","db5a99329d","495d7f4b5b","19893de75a","f446b3844b","9933e9ef07","9309915ac9","f5de472b87","db5a99329d","495d7f4b5b","19893de75a","f446b3844b","9933e9ef07","a69a0e86ae","cf94ea8c44","b19ea04cbc","feb4a2af96","c2a4653949","35608186b2","6f77d18c71","0d15f522e3","0f48eada41","fd83f5df00","9a481f7fbf","88cfcf4087","f68e778d18","47065b3d28","44aea5a6ff","99f694ea95","ba2802c782","de48970258","532e2d06fe","479d356244","2fc7ad0ff6","7d9a0514a1","095c541e05","e8e1d24667","e5d0f58091","b58d9b1f76","98201fde91","ef141a04af","2c41126776","918c90818a","fe05adddf7","ba3b96110c","eb8b0251aa","61599a664d","d1ee13c247","2c41126776","918c90818a","fe05adddf7","ba3b96110c","eb8b0251aa","61599a664d","d1ee13c247","a40373f5b9","f1405b4a1f","28ca8fa25e","fe9dbad2a6","298ef17a6d","a018b5c961","093b12d9b8","a40373f5b9","f1405b4a1f","28ca8fa25e","fe9dbad2a6","298ef17a6d","a018b5c961","093b12d9b8","d2d83a4f07","c5024e0ba3","ad28af8d65","e086f74af9","511fc70a2d","d7baa9f1a2","efd386e537","d2d83a4f07","c5024e0ba3","ad28af8d65","e086f74af9","511fc70a2d","d7baa9f1a2","efd386e537","d43a6336c6","9648d868ee","2d8403a0d7","d7511ec75c","4bf0cfe7f6","bcc6fa694f","904628b337","56eb2d1250","bae7292c1b","3f0dbf1e78","25e05b8b89","8c07ca2652","113f821905","780024a865","05aa895e16","67ce741f64","4189bbea5b","2a1fccd7ea","2fec16dca1","39c1badd55","6e0edff271","bc45eb69c4","b27153af38","00729bc53f","f65fe14ab8","e7ab741e09","0aad4673ef","a00f3d204d","688536d8aa","8ae75c38aa","4bcab18b15","af5aeaecb5","b6df2d17ff","c61283c27e","22ed75da68","8aab0a0443","1c970fd4ab","1251eb0d30","f66ce38afa","917aaf706e","e3a3ff83f3","b4c695cb2e","8aab0a0443","1c970fd4ab","1251eb0d30","f66ce38afa","917aaf706e","e3a3ff83f3","b4c695cb2e","688536d8aa","8ae75c38aa","4bcab18b15","af5aeaecb5","b6df2d17ff","c61283c27e","22ed75da68","66bed40ce9","89f2e40c8d","63ebbbf288","e83712c6c5","13d6950ab0","c48987cc34","17d8142a24","3a3df94d08","f07bf18269","24aeb04476","2be954ce26","64a5430d12","c9ef4e5b90","380f68b3f6","3f6ae8c989","77c64b70f3","fb5f3deb9d","dee0886bb8","87a592f84f","b75b3b52ca","377c56ebfd","3f6ae8c989","77c64b70f3","fb5f3deb9d","dee0886bb8","87a592f84f","b75b3b52ca","377c56ebfd","891de9210e","67bacba075","cb09cdebbc","06df9e2a01","d18a673cf5","90bee16caf","5d10f0da63","d6c63e6fa4","b03241065b","e8a979c235","e8eeec43a5","1ff859a6d8","246658c419","79b8b91ad4","d6c63e6fa4","b03241065b","e8a979c235","e8eeec43a5","1ff859a6d8","246658c419","79b8b91ad4","bd4e047aee","c410bf63ed","0f9758ff7c","b727d1959a","fad0efc68f","0d564e6787","66edd36eb3","550560c520","fc96a1a481","e191b759db","0a7bba0994","18550684ce","f002434144","30f7524356","c60a98ccd4","619f0aaeb1","c5bca38560","1260959328","325a76475e","1b1cd722d3","6b9487470a","c320e3161b","f62005ac78","ead72e1b63","f20955f422","4de602cba9","5bf9650d09","e568f8f1a4","892e6110b5","eefe1abf68","66a88b0531","aaf254fa86","b0622f0cf2","6c14a72c65","44b90a350b","41dc7ecb79","c8d20bbe09","25875769f4","8b1634be05","0bea8b7686","11af6c6765","288273864f","d75ad30beb","76e5ad84c6","c51621d804","b24f89a5fa","3f3a94b8aa","ff7aefac7f","dd8eea80e0","bd4e047aee","c410bf63ed","0f9758ff7c","b727d1959a","fad0efc68f","0d564e6787","66edd36eb3","677bc6e483","eb72a81703","0198935d99","c24ddf44ca","66ea65312f","0c5fb432b8","6ac74df050","7e19406553","1f6a1b2bf3","4dd1b36d03","348c1d469f","3cee32e2be","babac476d9","0e18a0c32c","d28f411459","e420ef6ebc","a83187d487","4fb06ad89f","e3a9191b83","0058597cdc","1d512d0e89","ad82f3d98e","9cf245d03d","9bf753e414","f10472366e","e175ea20b1","b99d92bb37","83cf04e4fa","ab4c538061","4c1d034d0c","bf8f021395","504b8b42cc","3364b46b32","8d0c7b95ea","ea401f50e4","35a251c26e","e1fda64cbc","c469b2b59a","e9545e5c99","56d93e6886","56dd7ab61e","c5a9ad4195","ab4c538061","4c1d034d0c","bf8f021395","504b8b42cc","3364b46b32","8d0c7b95ea","ea401f50e4","ab4c538061","4c1d034d0c","bf8f021395","504b8b42cc","3364b46b32","8d0c7b95ea","ea401f50e4","8530c8a17a","8d1ceff965","f2999ee6d9","a020d502cf","634912b68e","13d9968602","9f6addfd72","85ab1ec2fc","532e0c734d","4c61c130f2","4eeaeb9240","379cfc6426","d5ea9c7336","61cb6001b8","85ab1ec2fc","532e0c734d","4c61c130f2","4eeaeb9240","379cfc6426","d5ea9c7336","61cb6001b8","1c9313e3df","3fcf3782e2","948d78fc70","64802cfb23","e3b435edf5","a084e48eba","62f4167ced","0514637dfb","a3ecc7c646","873decb79d","4ac0a6ae37","53d2fed8fe","f6e508ae7c","69e9ebd029","0514637dfb","a3ecc7c646","873decb79d","4ac0a6ae37","53d2fed8fe","f6e508ae7c","69e9ebd029","b3c3be3ae6","b5a9456f90","20c4a055c9","6ba2dfe54c","3a6c67a1a9","c49c22eaeb","1544984e39","1ba1936dee","82a3469065","ce5014d8ba","8e177a789a","3277bb3139","15050eefbd","4c65fbabef","1d25731baf","e2d4ae3473","f2c9160d5d","5b3c052e59","64eb573b62","84746d6791","3cf001550a","545bd3590f","5bee47cd50","a02899eb93","b28a8cdc78","bdc3813eb9","77ef7a0f54","442e9d544e","9ae62123cb","9fd89a94a9","39f042bcea","9ce835ad45","e11ce52786","6b2417f691","7950dbf32e","3a8f55e36f","ca7cc6b5e8","12b054c748","f5d87c0838","aa340fd20c","43d7e5398b","9d183ab3d3","63d0ddc20e","db9c0c6b1d","d1114f864d","41685f4223","cecffacee4","25b0f4b986","530bcb381d","63d0ddc20e","db9c0c6b1d","d1114f864d","41685f4223","cecffacee4","25b0f4b986","530bcb381d","def5162509","39c7e8aba4","b9eab91ecb","5614f3f361","541ff1f2fd","c9c777c32f","e77e4d3a33","816edc5ad6","92e1df4ec0","a4e601a0c7","a8a9a37cee","9a4944d8b3","d777df029c","5003cd1425","816edc5ad6","92e1df4ec0","a4e601a0c7","a8a9a37cee","9a4944d8b3","d777df029c","5003cd1425","f9dcbc408b","82a30e59ff","8529e9805d","6bb5b1f92d","140ce6aacf","6851874419","efab790cf3","8579c970b8","4675013f45","7297a3b694","87793d0f30","8f3398bbaf","58021cadfa","0bc6735eeb","6a33160b94","0040cccd48","bddf2e8751","7d0cfbb8bf","2520bf39ea","edc293a923","7bdc9b8985","73139074a9","2cc96de154","7bce0a2b19","684482225d","f4f220b9df","921aaf193c","a7dc9ac275","6a33160b94","0040cccd48","bddf2e8751","7d0cfbb8bf","2520bf39ea","edc293a923","7bdc9b8985","22ae988714","e29013abec","723b4af423","7afc379035","6813b7ecf0","97a5fe40f3","822bbfc05c","5913bb86a9","b87e4d7f4a","3c7c9f7db8","3013c11778","49d557fc38","c23368b2e9","eef68acb9d","5913bb86a9","b87e4d7f4a","3c7c9f7db8","3013c11778","49d557fc38","c23368b2e9","eef68acb9d","38db8e3e4b","becefdc7a3","fe5d7d0360","2804ff0792","1134bca9e1","91f6dd9d1e","71e90c6b42","db2eea1823","12e3150d0c","7197f2a336","e69a5b0e63","0aabdabc02","8b02170caa","6604a115d2","a945655d57","a3295f04a8","a63e32d191","fd03356f14","541c65f460","7cc881ec23","d75fcbe9e5","4ba4a658ec","c5c8838080","e3063c4318","947894cde2","36ea13a629","14cd6259c7","e64b3cd856","c5a5be774d","ccc6c564b6","186d2ab5c6","e0cbbf3442","498199ab57","cc1f991b37","5afe432e73","2479b0db39","7a1a52a3c6","2ac4040204","a67dae27f9","56c5adaeba","5a2895d06c","bf4bf04da6","74e099b4fe","7e46519c2d","758efc87ef","2c3bff3838","66fe364a9a","fddb8af9c5","d8340c299f","db2eea1823","12e3150d0c","7197f2a336","e69a5b0e63","0aabdabc02","8b02170caa","6604a115d2","fe94e01b3c","a598dd9e1a","e2a3e4d785","ac7cd80fb3","4768d0d8e9","8bd470846f","d287f1b883","fe94e01b3c","a598dd9e1a","e2a3e4d785","ac7cd80fb3","4768d0d8e9","8bd470846f","d287f1b883","3cc89c7095","aef137ba8f","f607268f08","91485bb3da","8ef870c410","e2dab70f37","df34dbd12c","bc397d536d","f3a23e1aa3","0ca78caba1","ea2f1854f2","40434a6d45","88c7eabc07","471dd14b7d","664210e125","c83677f69d","dd5051ee8a","89d0176821","9530d21cdb","cf68608564","ffd7824c00","59101265dc","aa432b83a8","4c7cc0f564","e251cc0760","6a2778ec01","a1642ff41b","a2d98204f1","632610a386","f9c223591d","3014de9a97","aaae29ae14","d480a7c053","38d8949110","4d6ca74adf","3a551a7b58","abe7c1ebe5","0ce9b8d08b","c3c71742bf","da14be5670","0c4911f04b","41d4935057","664210e125","c83677f69d","dd5051ee8a","89d0176821","9530d21cdb","cf68608564","ffd7824c00","3cc89c7095","aef137ba8f","f607268f08","91485bb3da","8ef870c410","e2dab70f37","df34dbd12c","9fb28b2d73","74d54f9049","4f37b2df86","e788a1e937","540181dccb","02003e1948","7d6e963700","1020140e5d","fc2f8c2223","feb702b287","a8cbd1c7ad","8b8862614f","a62044c314","527229130e","632610a386","f9c223591d","3014de9a97","aaae29ae14","d480a7c053","38d8949110","4d6ca74adf","cf11c73207","bc1995f85d","11257853ab","451f7699a1","e6d4133e25","5b2981dba7","5b4899d20d","a38b3973ea","b217c95341","5327bbd8e1","ebb1d99fea","14573ee6ee","d7af76b64a","7dd9572d9d","5a435b9ba4","54be48b108","4a2aece461","15d85045d0","bbe9359084","5abd40e587","62fa9d0a12","7382c11199","eb8acd3d7a","1f17c6fedd","b20d796a78","91f48a6e56","eb2f9bd669","f026980e43","2417751891","be3fc0fb21","aa8526986e","5132e4f21f","83d2ce097d","eb2b3dfa93","cde583ee7d","829fe259f5","7c0475259c","16d43864ec","dd9dbc7102","115e76366c","71716faddf","3ccde7e722","a38b3973ea","b217c95341","5327bbd8e1","ebb1d99fea","14573ee6ee","d7af76b64a","7dd9572d9d","c551f52712","13b5698ea7","d24d4a7e87","2c3cb81612","1e54476c23","ca19a04e6b","1a4fbdad01","88899e55dd","73ccf72885","efe9d97ef2","b00be79f98","3346a0d06f","aae9d0e4a9","25a58ac7c9","63d69e2d67","9ed8d0db8d","9d3a03950a","94e0cf38c4","7abf18c982","f698b3429a","062488fb44","73c582645d","895c9f7946","fa919f6277","29d807e987","87ad6a75a3","f07266859a","43b81909cc","d52e0fce54","2c30598c4f","435c06b2eb","d0874736e5","487d6aaa8e","061d20ab30","329251e627","c551f52712","13b5698ea7","d24d4a7e87","2c3cb81612","1e54476c23","ca19a04e6b","1a4fbdad01","1786800694","910e6f8416","b26544c095","2516efdd7c","fd98a88ee4","0e1c3c7153","9a7c73c293","73b54ad853","7aae6ecb5e","da3dff5944","8ff1ee9870","e2c172b46e","b14fd695b8","1f565a1e6d","08c0afe024","5cca7d8af6","9243a9a39b","97c7a0065f","73ce0f3ac4","a2d9a18c69","a44f704f95","6c584166c9","dbcac90c56","ea10cf4778","0351635ecc","e814efea41","6bfd5b4309","161226bb1c","907560e391","76824944cb","ef65055e50","3384d8ab64","4f5a9773bd","760c2a43f4","d643bbdf59","8acf07095c","17ad4b3771","e9ee43f049","a27ff8e5e9","a35e6fade4","83b2e34768","f069a032ae","69f5cfa8d6","64c3b999a2","f64ca4117c","4be306d9c6","2d85a2867d","f94adf9efc","5702483ec3","83f0a2af3e","875fe3954a","1065a8901d","09d77ad7d5","798c8eb318","f10cae0136","d4465e39f9","f58eb2a418","df01fca1f1","548eab0241","050c91af09","f28a1c0a67","7ee989625a","4dee4f0ec9","08c0afe024","5cca7d8af6","9243a9a39b","97c7a0065f","73ce0f3ac4","a2d9a18c69","a44f704f95","f936b99d6f","2de7d95c0f","56f0a5de04","045ee77de3","4dc2694a47","1ccd6798c8","ee981b6988","9ade2f648a","acbccc4c67","c1d7ff4537","ca8e9fbe5e","24e86bb08b","328086d3c1","c482ff86f0","d1a5d08a79","a99df1574a","5d9390a0d3","c48ca16cb4","1a58511d43","9753cf44fe","d72251d7b4","e71f7514d1","a5c6f0f962","58ffd3be41","10eb0804cd","35f7c8f8ec","b858bb7e61","fcc89f8c06","75be511c78","0a47a3cde4","50860a0b0c","7f8cf28ff4","eac3be608f","10fee58298","0281ba3e35","d1a5d08a79","a99df1574a","5d9390a0d3","c48ca16cb4","1a58511d43","9753cf44fe","d72251d7b4","d1a5d08a79","a99df1574a","5d9390a0d3","c48ca16cb4","1a58511d43","9753cf44fe","d72251d7b4","c7927d7a77","ed044463b2","a757c84706","e538d0b7dd","f013b90d81","ce2be9535b","0e41773514","c7927d7a77","ed044463b2","a757c84706","e538d0b7dd","f013b90d81","ce2be9535b","0e41773514","24c73e3e8b","3ebe11bd41","c22c883b74","c6cab4b08a","fe4c96a62a","76359966a7","cfaf238848","1633b73ef7","92f55e3b5f","c4dab2af30","61fa7a102d","94e6b8b8b3","36549d89d0","ea36fa21ea","46f3e629ea","eed20ac295","568b439402","9ea9ce0679","52ab7e383e","88683897a5","7ef7648f35","98a692fb31","f5a2f1bd0a","a01dca9fa9","bceeb67442","3fe8acfc60","b177f65f63","28db17cd0a","f73b486ec7","8caf787fd5","9ec260882e","1fbdd5828c","747d05dd1a","c726f661e5","857e7262d2","f73b486ec7","8caf787fd5","9ec260882e","1fbdd5828c","747d05dd1a","c726f661e5","857e7262d2","c79dc71cf3","14521d7768","58d7b9f933","68a815b8ee","9570225d42","80e892bb62","8ab4729644","95a295945b","504ecf95ea","737c755152","1c017d8b98","a4adafd24e","8290142164","1884c98b35","ba3eb418e8","ddd0ed6393","642c52d72b","026c9da752","5445b7290b","42ab29e553","6641cdaef6","282e266cea","f6ecda91c9","190cb173de","4aa6f85bcf","0dd3dfa7a4","a2f1af5c01","c62396a861","28949ed373","27576502ff","1f02db8a2e","f87adea5b1","69e4c3bff1","021f9ebb25","e3dc67863f","f1fffc1cbc","875201a58e","8f2a3cc8a7","beeb1278cf","1994cde6c5","16c6de7c46","1c3602e958","ba3eb418e8","ddd0ed6393","642c52d72b","026c9da752","5445b7290b","42ab29e553","6641cdaef6","ab36571bd5","6c03b50663","a30bc3e46b","253fdf79b0","f69fba7b34","ffa234b11a","8cb8ae6952","04c1702a92","21b3cb6405","9e7a6899fc","8c751e3f37","0ac44e380e","48849025ee","9077e48de5","2bc673fd39","b50b1f5676","15243d6077","f97b5921dc","8fe3848a1b","0bea8c1da9","df35896cc1","2b82b9a391","58a8aa9fc5","73984ab914","b7a0b61179","6420e6cafa","bc27c26eef","3deb3ed453","3cddd53595","a2254f3a1c","c32b8e66fb","de3bc16d09","cf25b9c6ce","f0f45b8937","c6155eeaa2","3cddd53595","a2254f3a1c","c32b8e66fb","de3bc16d09","cf25b9c6ce","f0f45b8937","c6155eeaa2","6fdd53341f","edca38f44e","2323b47648","32de79bf67","aa4f7573f2","52e39cf859","f344c741d1","a66bcd8d48","45b1d2f81c","bc3c7823a6","be68842121","4bd2809ad7","495df0b9ec","42b4395941","3a9d61f5de","681d922c57","f3e70e3e78","c4a949c238","8c2b35bf1d","76ccded52d","51b4515cdb","d349d795be","a1fdd33f3d","9eb42b0207","caefd1aa12","241481c031","6d14a01d3f","d9bfabbb68","f790c5511a","6482f5043d","e499b23b7d","6da82d925f","44af61b32e","20d7427e59","04cb02a47e","dfa52d14aa","5306861c30","d55def36cb","6f3b37cf2b","458bdcbb67","cfa3514127","249ad2228b","9164e5d68d","4d81aa5cac","63b9f19b80","974739c7bc","db01ed2fc5","4e0bdcfa74","b7f330d2bc","bcdb00b52c","a98c46bb80","abf04b8ec8","8a638097d5","6a58abb8a6","358b43e386","e6c6d30f82","03faef1040","906aa16d6e","af4d60e464","b9d0ae04f5","9e85429fe7","f01e84f5ef","d3dba2b3c7","89e9286822","f09a72b1a4","78bf9fa35c","7e8a8e8e55","5ed0741dd0","d13d1ce132","a90d15be4d","89e9286822","f09a72b1a4","78bf9fa35c","7e8a8e8e55","5ed0741dd0","d13d1ce132","a90d15be4d","7d83f20341","adb5c5862d","7c4c931b38","6fb50abc5b","650737630e","b2f299d7a6","ff092208ed","24ac66537f","631111e87d","33d1f3ba25","c0b4372860","e881ec550e","21b8132c27","15e53f48f5","a47b2e7f20","9faf5094eb","43505beea7","040256699b","eead67b9d0","fa2a51b216","18f299dcad","e112b85344","81c278eea4","1d3d3bbb22","cce08ed979","32d85ba4e5","ca427a1b70","8246e494bd","eb129f2c68","e605285b0c","0529028eb0","e1869218a7","b849795211","c0e25d1523","9556c4073b","e064d0c307","bfdad7433c","0e2c8d470d","510cf4e7de","dfeb6d2df8","33e3fcee7d","a31ea7cd8e","7cefd073f8","77db8a034c","f985c1ed8b","db3f73f976","3928eb0e83","ee488c3b72","60c9a0ef43","89c96e880e","860f38e17c","162aa4554a","383739e085","f362b70d33","0da46c3cd4","3461f905df","0a5b559af4","8cb67ecff7","21ad081d44","1b3a78699e","b73737aed4","3d8f003f6c","c75345bf04","e064d0c307","bfdad7433c","0e2c8d470d","510cf4e7de","dfeb6d2df8","33e3fcee7d","a31ea7cd8e","f82d4a37ed","b3b44f3b38","e70cb636f9","84b18ca335","902cd74bc2","ada43f3042","e01a52af01","753dd6d705","46a0c2b773","3b87edc619","d1efbd68ee","9f51600f0d","c2a0c3c3db","53aa136169","b9dd973068","8e49759383","414b7bc866","e955c682c3","5e5d8e04e8","e45ccbcb27","26bbd96913","ec11f5189f","28a2d51255","506a17d6a3","fd5b164651","7dee9d7ad5","b789b8687b","11492e8952","beb3a323ef","09bd0680b8","0191ff0e8f","5fe6ad8993","6fb25ffa4c","cba689bbb0","503062d838","4ae443c136","194741d3ce","d85a85d528","fb4920fc7c","dc99a93042","c21296032e","d820abcda1","0768468f5d","70b44470ca","7c2faaf47f","4d8a197360","aaeb15ea33","2d1bc37177","79c560c931","0768468f5d","70b44470ca","7c2faaf47f","4d8a197360","aaeb15ea33","2d1bc37177","79c560c931","003cbe4df3","48d82fcc64","e7b5c72b82","7bc1e87cdd","fd6ad4baab","994046f13a","96c9ed28a1","e58d25d9ae","d5d187524f","5c9130e183","7e0127686b","b9e5987616","407ce28abc","f1156d8293","3f652019d6","6e3d5aebea","c00c0731b9","7299d5ba03","360d3178ba","6f995838a3","25ffb27a6d","9732aeb762","ac2a1711b7","f050442587","f323c67cee","e7dcde557d","5ff65c9426","73bb7205da","5e7fb9dfcf","f2890b74be","b776c0eaf3","972da0b267","e0e717b6fb","391906ea55","57ce6e4dff","951e9e950f","c5b83b3318","5b3b93f619","f30ad9942b","e97b3f798c","4ba18222ea","5e3239501b","3d4d379c6a","a1a167eaec","d388dd93b2","f2ba2dd7cc","67d310d336","342d353ba9","0faf61a3b1","8d6ff8382c","ee4df8906c","f8d75a3755","f8f758f57a","b0b0a4372a","2c8f6cddcc","67362226e2","21018c807b","4dc4259b5c","662d6304e7","92df32e709","641bb6232e","25f861ae3b","dbe08e1a30","21018c807b","4dc4259b5c","662d6304e7","92df32e709","641bb6232e","25f861ae3b","dbe08e1a30","9b3dcb53ad","7eeac7d487","3705ae63f9","7b409fd35b","cfc3842842","e66ca2e2be","fc768165e5","1d6743a9c4","cc6651fd2f","378953431a","b7d2a1e9b1","f62e846b36","e57dada86f","c37c9baa81","9e0557eb6d","8e71d4304b","e40e7e32d7","e7f51349ac","0733b3375c","7aa1c7f58d","97851bd8e7","efc0faf296","a850f5189b","e6aa8fab93","a8dd8df631","20efca1657","2c9daecf8a","d929978463","72a3016a04","b9412adb31","12252c3e83","df2d53ac06","e0efe5297d","9ccc7a2ae9","2a500f8138","66990d9944","3e4b54593c","10f20fb2fc","8f8cf7e69a","7d327e46b8","758593d0db","4dc0555b90","d49c5591c8","b89ac6eac1","029b0e8f38","eecccc977c","f9230bba5e","d1641a6030","35192eb4cd","b4c59c5735","98a30537dd","89c4cc350b","f7d4079336","dab680eb87","af9a2420a9","f676c17d8e","b4c59c5735","98a30537dd","89c4cc350b","f7d4079336","dab680eb87","af9a2420a9","f676c17d8e","d70e7fff5f","7b1ef9b9a3","43adc20cd8","ac914e5bf3","fe18df87c2","2e68d244ff","2ef76a5742","34d8604103","6fe0f5cdfc","a09aa44897","91f498a366","83ec92f46f","a62e78ee96","7bd35b5dfb","ea77ab9e2b","3241180f2d","eaa070d7cd","6521884856","1b6011d9bc","53ce5d9258","afbc938a15","f96b096cc1","0affbe36ef","6990e02899","a58246780e","7308becf5b","3097b14184","e4b4cff249","8a5bcec4cf","bdf7ad8735","f404f0f474","6dd7d3b00e","228b21dcdc","3b63aabb23","ca01cda1d0","294e0d37ef","e680acfe02","6d3c11a7f7","4ac02adfd1","8d0a738789","8ee27387a7","c4c1a30805","a2be504e9f","85c2815140","fadbd54547","7c9f6bcea7","611cd5cc04","354c6f1f46","a0f676b032","f6072b31bc","f5a98af93b","03c539a0b5","0c96c23e76","707ef6c637","2a65f04518","ab562834d9","f6072b31bc","f5a98af93b","03c539a0b5","0c96c23e76","707ef6c637","2a65f04518","ab562834d9","81aff2273d","b7e1cb1d5a","52a8993f99","d574171c27","7cb64f7583","d9c68f4638","7eac2c7277","7bd6249d68","4fad464425","2f7bcee715","03d6da7bc0","d3b0e4bb07","413041ab7d","5a48bc6b50","7bd6249d68","4fad464425","2f7bcee715","03d6da7bc0","d3b0e4bb07","413041ab7d","5a48bc6b50","c830af43d4","264fa3212c","d4970db73f","a6ee7b1450","f0299e86b3","0bc6edd109","dc6c1fd0a6","f7591fb32e","0ea16c906b","5b1b709cd2","3f03285904","97448fd6d3","b504434967","873b26c5db","9674e83409","94137de22c","c9639466b4","c81100eb65","4d31d4bf8a","dc739c443f","0463703af4","467e078e40","1f64ad9756","fb8813a77c","583a1524fb","7b8634a7d5","4383619ae4","f297196df6","467e078e40","1f64ad9756","fb8813a77c","583a1524fb","7b8634a7d5","4383619ae4","f297196df6","1d25347080","078a197e42","269eb113de","1446a74a76","739f2769f5","0787097f64","547b74cd42","dbbc1a7d20","02823045e5","8ac98a7cc6","35e29b055f","3ad65ee5cf","ce2ee7f895","ee11b63109","e0b024bed4","49c81a31b8","8f6946079d","ad12b90396","2021a064d1","f1304d41c5","4c9c254874","05b583c833","d3b025233f","e9d0ac8f73","9729fca4d3","e41c8b65ea","9cc1fcc6f6","c51c3e1ff9","449a447120","f976dde072","ace226b404","6ccc2a2622","13b871123f","0dcad757a1","b8272ec0c8","a13cbcd9ae","8d6b3a9333","dfabca4d22","96e114e4ad","6884911e92","8867acc195","d89c12fe8c","a449897ebf","144477a801","1c02516d75","849a80d196","66f9c2d3f4","376e417521","f6cfcab1bf","73c43d4f1b","2b62cf96a3","9206d0883a","38df2ec1d9","b797d706a1","f5f8a6d767","5aa9b55fdd","ae746eb2a5","400f98f15d","8e26db1250","38bdb9e29e","e839fe59c5","53245d8a27","bcf1bd3f97","3e0e9aa2d8","a85d9aabec","40768861b7","0731196148","c23b0c52eb","1ae1f03f06","f5d35557c6","f65b07e617","0b3a7fbfcc","dbcae02409","54cca51a8d","3dffb480f0","432a3c64d7","217456335c","c075146329","e69178d566","8d5f537772","28ddc0a6f3","6502f44563","700f588c46","5d1198c526","98c6acbde9","fda88effd9","e507b7ec15","e9a8c11e22","16e4838a91","9b84f35d14","d1d2f3992c","876258817e","e2b147372d","33783ed6e8","712b24c3ee","b5cd5e5b51","76a22af51a","613bb1ceee","acc1b2d0b7","9bc23c31af","773de6dfff","6dc6f6f7cc","a57e43f4bf","8fc016087d","cf6e339131","acc1b2d0b7","9bc23c31af","773de6dfff","6dc6f6f7cc","a57e43f4bf","8fc016087d","cf6e339131","5f7a35ae86","0469f82786","6611400603","19c6b52893","fba2fa5908","20752d4a92","971b440b2d","248798e1fd","b81b69f796","7a4abfbf63","2418ed59dd","3b3a7a6882","15694ede1f","cd76a65108","b67140c558","63280f2115","67b61842dc","c82f4dfcfd","a5055aa375","adc8142d34","4b1d64e82f","4a58aafb29","e7c097c4fd","6ebab157d1","2ab97e90e7","cafa7dc6a2","075d6c8d8a","bb34b4578a","0ba58ccc5b","dc2d2a570d","9dcb6d7dc2","09bdff316a","056e6d5bd8","1a198d6899","eb2f239799","0ba58ccc5b","dc2d2a570d","9dcb6d7dc2","09bdff316a","056e6d5bd8","1a198d6899","eb2f239799","12b8751c69","6bd9776ae6","d7bb79d362","bb0a628a65","12d2967cc5","b8b762ac54","5ce455197f","ee69e9014b","cd845189ee","3b3991351e","06c097c70e","86b2f78a28","a2025a4001","1d36e715f1","0ba58ccc5b","dc2d2a570d","9dcb6d7dc2","09bdff316a","056e6d5bd8","1a198d6899","eb2f239799","f42754f104","859b48d2e6","5da44240fb","d70ea628a5","77378aa00e","3ffb69500d","1e0f32b9dd","4947db45f6","412a295465","5095804791","3748bd524a","10f2a54bef","cf90c64627","46aab19251","333d70111a","e76c81e061","baa23ec6cd","476c7e61b0","f8b2b27e1c","5e816d150e","5504077d6d","9a45ebfe38","8a0f280aad","b1ce0c140c","a53bf12a68","8a571a1405","b6db307653","e15152f280","12783e3f42","5ab4988adc","3d2547a225","505f26b02f","a113618394","7a99c914cd","ce711942d1","12783e3f42","5ab4988adc","3d2547a225","505f26b02f","a113618394","7a99c914cd","ce711942d1","0b1a489954","a7fae5798d","a35af5abf7","d59ca12c1c","f983db9154","63f010e239","fedb31ab5b","0fbfbd457a","d7aebff7f5","240c21a061","53b1c5a4a5","a8e8dfad68","326fc89b2f","a598b0d1fd","c5fa168922","d9c92b24ef","4c2ba7d82a","222bdf323a","edcecaa1ad","cb2a144067","898f09678a","5f4308d347","b131e6ebd0","942f512183","6f4f78a548","27dbffd142","e8e7f8c740","2999a45b12","eed44a227d","637db137a3","a2c3bf7ae1","71a0b40c36","00c1301800","5b83c3e740","76b1976053","c9b2d4784c","f351bc1a2e","304fd0d1b8","5a0dd9a19e","ecf891e701","affa158604","d5686a5577","7b24be837f","57f527c7fe","fca038414d","0b80b882f5","36d22e0e03","b9ab780ee5","a9374630aa","7b24be837f","57f527c7fe","fca038414d","0b80b882f5","36d22e0e03","b9ab780ee5","a9374630aa","85f552ebc9","6e9e420dc2","dd3ccc1358","f6221b28e6","1d75dbd2cd","937fef9678","b6ce84a76e","8d4854005b","16b8b32bf3","fdb97f8f5f","268c4fcd79","04260e7f07","29e85e11da","9528f99bb0","a7ff5a6c7a","2395b998fe","adb5b33a37","455c3c6d6a","34816b214e","945fa1f75b","a7a31afdff","da5f7f961c","80a584c50c","0307347c99","edd9e33735","016e209a7c","a2c4f39e52","a072943a5e","d7c667a636","46327455b2","8fe189712c","20b12e1d13","91fbad4f94","99532f6984","1222107798","bd54019db3","dfcf136696","f2e1d12ca8","68159513e0","c02bc158d6","ce53a53a18","c60c9c5483","7d63038a7e","32b8e2cad5","aa9fb15226","4ad1b7f8fb","1496c4a414","2e31d3f771","5e9c7b3cf6","7723ba745f","76f01b6ef3","86555ca6c3","0dcf1115ca","1dbaca2da0","63c058d33e","7cbef63dd1","7723ba745f","76f01b6ef3","86555ca6c3","0dcf1115ca","1dbaca2da0","63c058d33e","7cbef63dd1","26862363a3","aa92121fff","5e28c974de","f5ceafe9c6","2c83520ee3","d7b0a4ca39","facfa8b695","5af149e42b","635464e247","42a6707766","4763fd5895","8833057790","794914a0be","6ccc936bfc","359f4d25ed","bd512304ec","188e5137c1","08beea1e56","bb851448fd","59f5ef9eca","10402d4d2e","d96ffbeb59","1bd84b515f","c2c29daf10","29f8754fd7","f32c58c1e6","d5cf4e3cfd","954aac4c2c","0dacce577d","4a77caae25","2da488624f","4f0bc99a26","d9c102a90f","c9f012ee7c","fad7b894b6","75101574b5","999a603455","114dcdb9a4","3edfe857bb","eba288f7e8","9e7d1d57ba","666a1bd6e7","7f9eb6a1bd","c9c1347af0","3d6f6b6424","fd0e046f58","91e30fd255","15942456fe","acbfd3816b","7f9eb6a1bd","c9c1347af0","3d6f6b6424","fd0e046f58","91e30fd255","15942456fe","acbfd3816b","7a59321f8a","7cdc6ba8c0","37d8bd4089","9faa0bbe11","2c1292d1c8","d771649dd7","518ea11ec3","28bb59ed7d","18d18ce3d9","208f463c1b","7dee1e1419","579dbd34cb","6779f007e9","3df1c9ce98","aee9154cff","824aef6f1c","fd6c97547a","3c2c6270e8","f0cd240578","b639f4c8eb","1fd3fa8a06","d7cb9811f6","0869194ad8","62b34c4c4b","a920a7342c","d9d66a3189","189de7cd6b","a06e680850","d7cb9811f6","0869194ad8","62b34c4c4b","a920a7342c","d9d66a3189","189de7cd6b","a06e680850","477a976157","072fd84e86","bc04f83969","56bb127a39","88faa6bdff","df00db3f11","bae23c4317","cd6d61d033","cb86958d79","b3ed6ec4ae","aee6745fb9","dc204a9918","589e68c5db","b9179ec702","3f3c3263c1","ae762b3c8e","e3e41878b0","b180d8b053","ac1a594821","394a90ec3c","e050d52d59","e934d6f8e5","e2c52f9c57","1acc90a7b0","8c91a985be","d2d013090b","8e8c731cb2","d697925238","4fc6010461","a50a0bb798","4302443507","b9da67f597","abfc29316e","a4ebab77cc","0deed810ff","8873dadc0a","0e02fc6d2c","4a40a86daf","eb6ca5d68e","90117c60fc","4a087f838c","259f17e87b","52f30b503f","18a8f4cf51","1b86104743","1e744430db","cd8e68c01e","176cd2c4a7","2cde8d063a","fa1aa9cfcd","00710c88b0","9e6ae02931","58e850dd27","ab3bdde2fb","67d8001095","319f4fa2a2","52f30b503f","18a8f4cf51","1b86104743","1e744430db","cd8e68c01e","176cd2c4a7","2cde8d063a","52f30b503f","18a8f4cf51","1b86104743","1e744430db","cd8e68c01e","176cd2c4a7","2cde8d063a","67343d5cd0","0d821c1093","3aeb644f00","bab0329339","1c440b29c5","c43aa2ae3f","159cac7623","b8a2807d71","e42cee2942","d49e45398f","6d7a7bc2ba","f8ad858b97","80c59d090f","47c5c8801b","b8a2807d71","e42cee2942","d49e45398f","6d7a7bc2ba","f8ad858b97","80c59d090f","47c5c8801b","8679409437","846b0b9b9e","a39e666258","a22b94b162","29945805bd","cb5dacf855","b17fd461f3","c9e407d32b","d53ca5f0f9","676544c1a1","e9c821dab4","3da2d146ea","e2c3f0daa5","0b5119b59f","8a61154b36","95f2a65dce","012097e09f","f125ac48a0","aa83b1f07d","2b16060ae5","1e5ccfb7e2","88a1098b07","071931e0aa","e7597291c7","1339f0f24b","457c88e94b","ff168487d6","2b86735ef0","496ff7781b","c6a55927d6","ec07d8280a","bfdc4b9cf3","feb460f5f6","e0099cae8b","39956db65b","6aacbd6c45","c1da34afe8","ef9425b538","3741c3e79c","808ebe79ae","7ea49c7080","5fe86da53e","359cdc3594","37c4c8b8de","85c95d24a8","6d5365c007","aab55b0f95","e581a2232d","4e1f3a1dbc","11abc0a5a1","abd8d5977a","1cf8919f6e","ff4bfb200f","3bcb42fb62","6acaf139c6","849443fe19","6d036071da","3e3b3a1abc","6da6abe20d","77a6a105d7","97bd0e81c9","fb48b07720","d630d80606","2ea5c2027f","022b0fe271","b97e41d915","12fb23b89f","61bebea26b","51e131c88f","075f8a9f75","1eb0c5ac42","3ca6c3b466","46a2ebb570","c4e906aae8","eeef1cb1a2","38ef29071e","047bb4091f","1ffb5338d4","5e36152b4b","5b778c67c3","cff98b50d6","c4052ec9a4","b6da57f3ca","e18bf61a95","ffc8723762","622c502f30","79d2fab144","4a47922460","3681eb0452","b8336e4814","45f595da13","ffc8723762","622c502f30","79d2fab144","4a47922460","3681eb0452","b8336e4814","45f595da13","3cbb23e7f0","eaa5c92b8a","b99e20ce95","46a1b84325","ac702b9894","6fe034c1cb","5c3b8e5619","1c343f8ea5","61888059df","3981a72452","f346d5ce7c","093bf93b63","13d930a96d","a1d3ee4f1c","1c343f8ea5","61888059df","3981a72452","f346d5ce7c","093bf93b63","13d930a96d","a1d3ee4f1c","cfb67aa5ca","165f0f5ebe","95158b0e46","90e6c5d4e3","ee9c2e3250","2e1250da87","8527af8a29","4373e06e36","f8ef271b10","e927147761","36e44713fb","c005efe392","6083ddec96","7243c4a02b","febcc4c663","478dac8e05","daa09c771b","e08f96c904","7dd608dc79","e1efc7d5ff","7b7066ee58","73c7807eba","79de349f38","c9bae911a9","de49d8fe5b","675235fa55","687a887b2e","4b4ef98242","914d2dc566","b25b20602b","43d0f45597","a74ebdd396","3fa7d9375b","b3019e8ffb","4189796327","3283fe451d","dbb70cd612","9dae91626d","0958989cc2","cb7f39c514","7e94695218","5579452ae7","6bb06e3ae4","d773592567","760d6cdd55","d6fcdc1681","8e85cafc72","105cb298d0","d2410ffab9","6bb06e3ae4","d773592567","760d6cdd55","d6fcdc1681","8e85cafc72","105cb298d0","d2410ffab9","08077e9691","fb0b371739","8ca35986a5","8d52b8656f","7b49891100","06168d5951","d5fd1f2018","9bdb0b2415","d26b7caec4","3a9b0e4be3","ac85cad93f","a1b4307928","d9a0f684c1","69c2be2836","7e1754aa3c","e11398172c","326d7a2ef0","2da25a37dc","7600d89ced","e757f22623","e7e22af90d","3df88656f7","ffffdf24de","4a033dca3c","50da9c32c2","9faad19118","49bca348ef","13f5a4e246","29121e4cbe","123d27f471","665ed9a761","875c60601e","2c9a45bb73","19f875630c","9b1392e64c","d964b81f02","dd1580faeb","0812018a5a","09edfcc7e7","bc5db967eb","d3f7e7a2c1","f2ea4f6e3c","8aa2504254","5d70048c2b","cf338aef41","1f2a81e89d","f4ba15945a","7d9f1ce128","044f9cc0eb","ddef691aee","97bd62c43e","98bb7deee1","edda5d91ad","803ff3781f","23d23e74f1","203d73c3c4","4a2990aaa6","3ba0080052","120bef572c","9d75edb0e1","4560a6e1dd","90c19cb5ca","463d88cc38","3ae98ed931","1ebd29e7c4","885e4d0fc3","e86c290773","7c8c8a88a2","a96c7351f1","818ee6bb68","9cb7209bd1","ac1515f275","8350aaae94","0a540f7db1","771557284b","d0bd67239f","928f93ef14","ea8ab61d67","b7f1653a8b","bfc8318f2a","bfea7defd3","8a9fa24d1a","8e150c935e","8f184c2833","e4d980d24b","ade4892ccc","e91773eb10","6701abec46","108e18a36f","ae4a8cc4ca","6185ad6f09","e4d980d24b","ade4892ccc","e91773eb10","6701abec46","108e18a36f","ae4a8cc4ca","6185ad6f09","cd6930432d","74336e11b3","ba31a10b1f","3e32f893ef","13978c5c07","82097f76a7","15272f2f1e","a9aeb8b511","a5d44421e2","bce878d884","c32e99f995","0a90b409ee","31edef367e","0340a7407d","35598c56e3","41812b6b27","f5aec22aaa","a3205b93dd","1cedbafb70","3dafa09094","ab37465dba","62191ed76b","ad8bc9b6d1","3918778b91","92e2335c01","3f7f3b6a60","61d6a9c156","341aa81e9d","ff073052e8","ea89b8820c","dfb98493ea","867ef9e624","2a38888ef8","ad3b3ab64f","4ecfe83972","a9cf59f57f","a34066299a","504b353556","0c26573d5f","0c902f8b09","c5446659da","3158ddeef0","5ad3cdc442","dfe436f90a","122be8f128","d1297045db","3bdd92b4f9","d4e917cf9f","1b182530cf","8f8d873a9b","9fb7bb4306","d0dca0a81c","0c8264b5cb","eeb05cfbdb","540479bf24","46dc6bbafb","6358be4d69","62600c8ce4","9af82a7336","64963f61da","c1fdb607c6","7d21fb461b","fa5765a68c","6358be4d69","62600c8ce4","9af82a7336","64963f61da","c1fdb607c6","7d21fb461b","fa5765a68c","5c7fd01ece","3d1e07c127","c4b794715a","2e32d5f1bc","186be99900","4b8ec9210c","ed21b59a35","fa55e1e008","fcccca83f6","4f355bc680","67dde46a25","202d4b475c","19b8511312","2f6ace2d60","1a0d2312c1","b3915e90c6","900c0ca1f4","53f87e4cc5","cef78450a7","b35e4003c3","fdfaf1cdfc","5c7fd01ece","3d1e07c127","c4b794715a","2e32d5f1bc","186be99900","4b8ec9210c","ed21b59a35","d160961b21","1b0a7ceb04","af669d8538","942fea89c6","9f1afd756a","0b2176ae26","2deb93e3b2","9987b0e75e","e61a4440ec","183d8a2aba","c0d75b1026","0f2b67692f","3c918f823e","9125794e1b","0957795e6d","e05f07a11f","046cb9a5f9","4ce003dda7","c84fc0f145","92c745ac29","023bbdf871","7230c47836","b54dbea52d","fd5187bb6d","13426557d2","b97ed38468","239fb1bb14","5760b1d372","4a51158ff7","aa717ea0b0","e7201af2ae","778d357b21","c5d12e6e29","7c68079d71","cdbd96ff01","dd5d9ccba3","dee3c0bf61","1bd61dedb0","7f9f96bf06","d59eae3710","06819e6eb2","cffcc2344b","1816bb9118","917713369f","ec3c25ed76","679599ff36","99a512824c","572c16bfe4","0d2858098e","2ab34df927","2c6040ceca","1ccad1bec5","031bfd8d26","7e63a5d91d","e721e66c2c","9e2633bff7","e7fa32b59b","560320dde7","ed92a8ee91","55647bac26","e24159b7cb","b7ecc340ed","4b2b5382a1","4d32543a11","ae47c94225","4ade7477ac","16ab1c0680","2601f53ee2","a1ee907754","24e23a6a2a","69eab62215","d6f9f022e2","2e63ab4116","5f9803051a","f0bd7def4c","436d4c3f48","2cc47512c3","69eab62215","d6f9f022e2","2e63ab4116","5f9803051a","f0bd7def4c","436d4c3f48","2cc47512c3","39845dbc8b","2d2b5a2b9d","0c1ad790ba","0474bed869","b2f7ebbde1","dadb14d08e","ec168a38d1","a9a2aee8c2","082f176c15","a51ea0fa29","0a7998bf93","66582d45c3","b39468c069","7f288d26ed","b732c7fd12","12fbdfc3bd","f420172b84","55a7d25dcc","2c6ad76509","2ef98d89a1","f1a7a95c8a","a9a2aee8c2","082f176c15","a51ea0fa29","0a7998bf93","66582d45c3","b39468c069","7f288d26ed","a63da2ad7d","6676a999d7","5ce69d303f","7a26a924ff","704f44ccc2","1a6aefa714","9a253a6451","c7f85732b5","c1826cb73e","5625e7b32d","86297cff1a","8a327114a0","0dc97de02c","3ed68d9fe8","01902bd0ae","cae625653b","6ef52e6e28","1470186d02","623f7506a0","d90f37ff9a","e8ae641e51","ca8b178f0a","21db1435fd","b0e2ed0e37","39c0b244f2","fd2c7fdb8a","1e7f1f629d","88483d82bd","4536eaf304","7ef9a23bbf","acf09989cf","cde2318415","17deb35309","4f75d7b9a9","b9cc41c0e8","503c285acc","8edcc61647","2cfbd14496","ebb0637a05","2d861ab337","eead64c731","931e54642f","3487287df3","2348068abf","084f7fd991","c6c3133aca","7922942fa7","5826670bd7","3e0d1088fc","2fd364a9f4","5294e20fb0","9dd4f43b26","42738daa79","ff24937216","3a89b7fa0d","619d65aa7f","2fd364a9f4","5294e20fb0","9dd4f43b26","42738daa79","ff24937216","3a89b7fa0d","619d65aa7f","0fface5392","611f7e3ddf","987847e9a1","f8f5cbdd36","6bd49efb9d","08120ce475","96daeb9d22","5a9abbc175","10fbdd3b43","3af77c4250","bf5dc7e0f2","1749fc78c7","12d8c35788","d8a57419b7","4a6ef36f43","0ec8f28f17","ccf7e33a1e","9901c66de5","1ead7271c3","789dd68b90","038581f7ce","4a6ef36f43","0ec8f28f17","ccf7e33a1e","9901c66de5","1ead7271c3","789dd68b90","038581f7ce","bb574c8eaf","6eccd27ceb","b02a424d97","307b1a5f17","65d2bb2ae2","ac0f4d0e33","9281455a22","be91eef416","97998620bc","1db03b6cc0","677025c22e","23f34ed596","c00c22941c","637ed6e70b","be91eef416","97998620bc","1db03b6cc0","677025c22e","23f34ed596","c00c22941c","637ed6e70b","4c02ccbd46","223d492f0f","cc55dd9e81","eb89b967f0","d881809f67","7891145d55","0cf594ea99","b7e6bd7ebb","4fd484fee0","b0f092cb46","6df36c0a77","6a45f6ec23","f899a976c2","c3b2559410","b7e6bd7ebb","4fd484fee0","b0f092cb46","6df36c0a77","6a45f6ec23","f899a976c2","c3b2559410","2ba742b826","8d75997226","77ca6125ba","fa9b7327b1","f514076efd","6944ed3d7a","d2811efa68","a0f13ca859","c087f89f9c","b95b99a9b5","a24c404d68","4befb96cab","c8c4090d6d","b8df54c34f","c454ad6ada","0275eace10","0894e36ecf","83e4487b6a","c72e98ff46","4579dc3994","6d193e07b3","d808aa3409","022ce59d5a","41524dc981","33f1651222","0775d9fe18","a309d3e5a3","9558587093","20f7fd1b25","f013f3c5c4","a87bd06b84","eb70dcba3e","06451b0b5a","7ffc085826","241dd2866c","8454ba6b6d","32fe1c5f46","102fd578e3","c21adf1959","3035262fdd","12b07419a7","7b091ffeaa","2c5e21988d","f603423f4d","575d71a186","83b51b6a73","033b58c0e8","0eb3eda612","bf58f7ef3b","8a6a0eb6f0","1e4443ca63","4459ebc616","d7b66080e6","cc5cfdba7a","47fce41c41","ed221565d9","d808aa3409","022ce59d5a","41524dc981","33f1651222","0775d9fe18","a309d3e5a3","9558587093","4a2a9e45fc","a1546cc714","095642dec3","19091538d5","a7b38b0d0f","8ec40e2c3b","0ec853e44e","47343f5f88","5bcf7eb88a","042992291e","d0ee800875","6346f7afd1","572e338fe1","1878a2e5a4","5802c45c3e","22cf88fbdd","723a7cb2c3","74212aa86f","2bdfe29866","a581e1b028","e311ec3eed","5802c45c3e","22cf88fbdd","723a7cb2c3","74212aa86f","2bdfe29866","a581e1b028","e311ec3eed","ad8049825e","a73cb2d9c3","14bef252d4","37ee73cbd9","00acbc902a","076f55e8e1","cfc57cf034","dd8ff088a8","052fcad1ec","f81df7aa48","96bc207805","d2312bba27","2c76075a2d","76326265af","468f1032d4","e7061d1aa0","671d70edea","4855b3d4cc","814e57f7c0","93b5a14562","ebd49b6488","592a761b08","203f927569","57b446c26c","a393b0d436","ae45dfd9ec","8ff04dd3b1","108cae9f3f","5c07152734","923980d2da","91435c517b","739deaecd7","029defdf9a","0518c4a8e0","43be7497b8","78b887a058","dd1e45e301","dc64a51bbd","0ea68de3d0","ee56d43d24","5e794f0b64","d2f3e4bfdb","1924cc0d13","aac353f035","180c71fbdc","de50fe9b20","c48d9deb8f","149c2e86e1","3754b90a40","1924cc0d13","aac353f035","180c71fbdc","de50fe9b20","c48d9deb8f","149c2e86e1","3754b90a40","4e6a7f9621","7f896b4bf4","2d03bd98cd","ba2394e4dd","8891865a00","29afcf3b88","30521d41f3","a3d1ff5b16","fd2d32d281","d9ad91762b","f0ff0ea319","4c90f62668","4a6b6954a0","503a358540","a3d1ff5b16","fd2d32d281","d9ad91762b","f0ff0ea319","4c90f62668","4a6b6954a0","503a358540","5373bb338d","86a06720e6","d86751b33f","199a58cd38","238859ce89","9c9a380865","8a3ba27a71","b3b1917e91","3aae5f4c55","b3769ba557","962cdb4d3a","0b562aaead","c66cf832ad","18fae12b63","bd03cbcec5","6ad9d8ec57","8106e146ba","7574f5f3b5","99b5c1bbcb","d2ee1a1c00","a421f43623","e2bb6d5eb0","da9eb1693e","97c1e081f0","fbe115e80c","bce885406a","9333abf1cf","6bb582e38e","1cc28198d4","2a38b5b74c","18e6c48e09","97f1bbf899","950035eaa6","165f1d7537","03c6b5dfe9","52261abb50","f49a24933b","8dbe06f90b","046380bed0","8a190ff5c7","638ced5c76","8c6b3c8922","bd03cbcec5","6ad9d8ec57","8106e146ba","7574f5f3b5","99b5c1bbcb","d2ee1a1c00","a421f43623","016430bb9f","05470c58f4","9f5d4da69b","aa5a640f9a","2662a40ab9","7a70691f53","8fefca86bf","016430bb9f","05470c58f4","9f5d4da69b","aa5a640f9a","2662a40ab9","7a70691f53","8fefca86bf","3cff8d2095","4eca56bede","17efbb94c7","5515968104","5926be5be7","a477bff131","a7b2ae9060","2bb4e24659","b44a5372a1","408871a043","108a5ccba5","92a987ad5a","4152f75f4d","09b4187937","2bb4e24659","b44a5372a1","408871a043","108a5ccba5","92a987ad5a","4152f75f4d","09b4187937","e7da9ac9c6","62d9039c71","6ad561ea7e","3063a45650","e4e1b78e8f","f153e20a5f","71215474a7","8f31b86f6f","df73037a65","842b57c7ab","b115c19497","368617a19d","d8fe7c9f26","929ab59129","8f31b86f6f","df73037a65","842b57c7ab","b115c19497","368617a19d","d8fe7c9f26","929ab59129","ab09e02c1a","4007b94998","440cbd715f","aea164b9ae","5d20aba8e8","98e0f7f149","cb69266a4a","7f0f40e620","a2f81764f4","21c00d171d","2a01f7311a","e9c88c883e","41699378c6","db3454b83e","c0096dfb07","9c9eda1a9b","eb24e6802d","9a41c35905","e86ca9250a","46d8476adb","bf03df17f1","7d5c0624d7","a4b59cf45b","1d3dfc9b8c","ba841d18fc","17d960fc8c","09edcd0ba8","d00b159490","64591f3b67","c17fdfb47b","d7135b483b","d5985e38e4","e2f76b70ee","644364bb8c","14ac64568d","64591f3b67","c17fdfb47b","d7135b483b","d5985e38e4","e2f76b70ee","644364bb8c","14ac64568d","e3f9f1fa9e","8a390cd6f7","d73437350d","953af8dd32","4b21041b68","35facac296","6808f77853","7d38a5e6c0","6f3c390153","22ae18b050","616499e9f0","6540ab6dca","d34afa9b8f","6850229c3d","991fdabb16","ded7a6d4a9","58e52001f7","97c3fc7156","e5b65c316c","06613787b3","80cd0b32bd","02aa22ed06","9920c399f5","147c162dca","6e6ab345bf","843ddb19ea","38113f3d15","c51703cfad","0c56ef0802","4f266179f3","38e92981f1","ef573a6369","5480264cd2","9210b130f7","235a5a90fd","7d71501701","4bbdacc5fc","41d1a44dab","0ae24831d5","86648a5660","9590cda1e4","f54fc6023e","5e37f9c9de","861a1ace8a","7f44391118","42ba4479f0","09ccf1a02c","85b7b75a9d","32e8ead819","eda2a5f0f4","8fdbd3b766","3e3b8d5c5e","afe1a685ff","d1225325c5","72d0a1cc63","ad218f5e9c","7d71501701","4bbdacc5fc","41d1a44dab","0ae24831d5","86648a5660","9590cda1e4","f54fc6023e","7d71501701","4bbdacc5fc","41d1a44dab","0ae24831d5","86648a5660","9590cda1e4","f54fc6023e","ece28abdce","96d783cfa8","bfb02db959","e338edfa41","888a881d33","41b63b693b","ed7b17e49f","f683b25136","f0cb76121e","d5bb42079d","1f620fa280","cc5e26ddec","7e863c74bc","80cd1c7a33","fec665b12d","ea0eb858b9","4c5ea8a252","4fe14d71de","0a4555cab5","c6ac5efe06","f4ef86d771","89a7faa3b3","0578838d0d","c8dbf3c50a","82eb7acb34","62c6752446","817e6cb98a","c5c6b3c4f8","0f9bf43e63","e9074892c5","2c20222a41","f8cd4c84b7","92e1c03672","f852de48a5","080b6ca2e4","124d1f4f82","605f6f802d","d58cef90ce","ae327b44f6","65a2e469a7","73a216a886","5a8204cace","124d1f4f82","605f6f802d","d58cef90ce","ae327b44f6","65a2e469a7","73a216a886","5a8204cace","40d78b343d","4ad277abb9","39792ca470","f20c475536","3d3b7aa824","146a2ac079","006f2a7fa0","1c2ba9d5f2","d97afec4be","d4fd8bd64b","848ca32780","93746318c8","8e06e6060e","48c3330efe","3388450be3","e8fce11ccc","6ccd5a068c","8b321f612e","58f50a7358","bb9fcd60f9","147c2a61c3","24ecee3086","4b23eec0e0","299e361b31","fea4ce6a39","0e4cd5b457","8ddc4fb920","4290a279da","27fcee2093","342d46aa18","2c564c98c3","aa7f5c8d09","3d32d246ab","9369a57df1","bfdd5d5a53","1fa6dbd626","94180f8d8e","7a8eaa2ca7","67240624fb","ce43663661","b7618d4f14","9dbe730ced","1fa6dbd626","94180f8d8e","7a8eaa2ca7","67240624fb","ce43663661","b7618d4f14","9dbe730ced","50d61a06fc","e5a22ddea6","e85e7cf41e","475550351e","fbda750e0e","628303ace2","c49adc6fbd","614e590e97","56f3ffafcc","53e82fc298","b0a7bfd775","f6cb5529b7","c67e932f2b","bc2ce3d04d","614e590e97","56f3ffafcc","53e82fc298","b0a7bfd775","f6cb5529b7","c67e932f2b","bc2ce3d04d","614e590e97","56f3ffafcc","53e82fc298","b0a7bfd775","f6cb5529b7","c67e932f2b","bc2ce3d04d","01fedfc319","ef3d4f7013","f0d3a2a771","bb48948abb","61d852f0f1","1fa7de38a4","2799224f16","c3da1ff0ae","9d3641c542","f7afc7b323","20af04cbb9","11353945e8","60893cf2a1","623d3e5fa0","c3da1ff0ae","9d3641c542","f7afc7b323","20af04cbb9","11353945e8","60893cf2a1","623d3e5fa0","c3da1ff0ae","9d3641c542","f7afc7b323","20af04cbb9","11353945e8","60893cf2a1","623d3e5fa0","d9101aa49d","33e172fffd","b2fe3a9aa4","034e8cef91","af3652eb3a","f7e23c94d5","527d4d4205","67ec8f73a5","7d05e3b04e","800078e327","86f0c5635a","5a5f67f0aa","df969a506e","e31463c9bd","13568ee434","cb1c853369","5990293839","ff6b40d9a1","7ca8c929ed","ebdb505d06","d84379858a","6bbf873f8c","ab0640b691","3f5261b593","e197d624b3","bba3f3a7b7","dfc30dc4d5","211ea00f41","c46750ec6e","a2bafb8731","1a14d20a15","efddf20109","6fe51d5c2f","840928fc69","d61a94dd9e","6c8b721373","72cd7613d2","faebe24f8f","b2807ee94e","43bdd1d41a","0a84ba5ae0","b7c9195370","c46750ec6e","a2bafb8731","1a14d20a15","efddf20109","6fe51d5c2f","840928fc69","d61a94dd9e","698b7b457b","cec1e721d7","a0b28fe5bf","fb6132fd0f","3ab6e0f572","9079ca6e5f","4c6672c59f","9a10327bf1","acd5f01c1e","9c9481e197","a2c6813557","20a3bc0551","328b1b2e1b","c240cfc1e2","eac5e080e2","761e8150c2","5831ed801d","82f06f37bd","a80d79bc7b","3225857660","e7cfe2e824","aa6c051726","3c8f22b398","c397d066e1","37d4fa546f","3b58342aab","5bb5e36e44","5c39a37b8f","aa6c051726","3c8f22b398","c397d066e1","37d4fa546f","3b58342aab","5bb5e36e44","5c39a37b8f","ad7df86adf","7c191bb03b","100c4faa73","32e0cd2912","bdbe1d42fc","839f0ef2c9","f8ce80c70d","33d9bed228","d34f596dfd","5341ceedf7","09a94639d5","5b9f6601c7","1c4a29b388","8f85220aa3","1dcb22bc71","95503df766","fca07a9cde","4180c58eb2","c468fea6e6","f03680b92a","e5d5794ff9","c1291768a8","eed2a899ae","a02cdc6761","c5d1617fbb","95debb2e94","736fc57b6f","dde88ed3c1","c1291768a8","eed2a899ae","a02cdc6761","c5d1617fbb","95debb2e94","736fc57b6f","dde88ed3c1","16aadd31aa","0da856415d","2e8a456758","1fa3c6e74c","a043597222","e42a17b019","4d680a246f","d64232b979","5e39ece24c","f755f66c16","b3483dd85c","5e578013a2","8c1ce31484","a56beca673","b9def283f8","aa2e80240b","d3395dbb71","823fa95ac5","08db8e8c2f","398cd3a431","86f494031b","bd3636fc6b","c51a2892ce","4341ffae39","f25728ce9d","c464c32dcb","99f505b81f","b94413b20b","bd3636fc6b","c51a2892ce","4341ffae39","f25728ce9d","c464c32dcb","99f505b81f","b94413b20b","f4ad5157e8","ca24f1ca8f","4e2f6b3290","233b1ca638","0e3f2aef14","656bd5fe54","a5480830f6","72b469cb0b","f558b8d90b","488e5aac8a","051caf7326","80e6390c98","d0903a86a5","7f49adc8d8","ed5f926ea5","d912da9b3a","95457e5a4b","6654970535","ccc2702a26","1c1a5cdc7c","f9195f0fc2","c7e33e7139","ad0538fdc0","94c793a843","bd68c6d558","e4ee88097a","d501a5bb6c","5e66400fe1","69007c47e2","0b45d4607a","ab53164bc5","1bf0db4854","f87fbb7026","88d1568268","8e3362266d","6270639a7f","62f498b7ee","608ad50aa5","a7bd747ccc","a76ebfde5d","a7ee5aee1e","045656a01e","c639115046","a78431132e","1240e46e97","64b2283086","fc028c503f","f5fbf15d00","29a663e0fd","ed5f926ea5","d912da9b3a","95457e5a4b","6654970535","ccc2702a26","1c1a5cdc7c","f9195f0fc2","ed5f926ea5","d912da9b3a","95457e5a4b","6654970535","ccc2702a26","1c1a5cdc7c","f9195f0fc2","8f99182eda","0abe55cfb7","132645b695","44fc2d890d","f160eec857","bdd618b6e4","8839d79324","8f99182eda","0abe55cfb7","132645b695","44fc2d890d","f160eec857","bdd618b6e4","8839d79324","99176c1e4e","2af07b11f9","1f66366c8a","1ff891be2b","956c08314e","b8d74b50ba","1d80e0a2e7","2e082209be","7871a74f7a","7c5898674a","93c4c5f3cc","2844c6f665","fd1835a206","4386dc9745","8b1f81ac42","86ca4cd5da","4160d48fbc","8a28f0f050","68f8738233","3536a25074","fcda76cfc9","8d1baaa6c8","b6adf33f16","44e525b0c3","e5c4592d90","a90d27caba","c1edddd4a2","d8942b596d","1bc2b3167c","136fbb106c","adb3da083e","9f47995b33","d75fcd5022","b02b0cc79a","a37fa6ee92","8d1baaa6c8","b6adf33f16","44e525b0c3","e5c4592d90","a90d27caba","c1edddd4a2","d8942b596d","a739d366b1","88163f101b","8834dfecce","6042b81119","e5b94b75b4","091c6669ad","cea28ebe71","a739d366b1","88163f101b","8834dfecce","6042b81119","e5b94b75b4","091c6669ad","cea28ebe71","a739d366b1","88163f101b","8834dfecce","6042b81119","e5b94b75b4","091c6669ad","cea28ebe71","92a4f7edd6","636f79949d","a9a7ee2a03","b89892d6f4","c4f2ed9dfa","08130dd636","c692aa12af","3820ebb28f","16028f77dd","8a218a7c93","dce614619b","70e871071c","6c66f63f3c","7254353eb0","3fc49ee261","3e54664bb7","fd1a9bb265","9abcb6a6d6","2b0cebff6b","14465204dd","a9319d21d0","a0a67ef5c0","b4e3677dba","dcf446b85e","bd4385da00","7c80f85eef","1022b38148","ad0a51a906","eb4fbb9933","1b040eabc2","9baeb31ff6","b4140bafe6","7c36fb79b1","0ebd71af23","fdc1bb50ad","dbfed21117","af85725ed0","6295b1821d","80bd8ebe1d","3f8e56c8be","84acb045a5","fc890d868a","dbfed21117","af85725ed0","6295b1821d","80bd8ebe1d","3f8e56c8be","84acb045a5","fc890d868a","bff35aa7c2","4f082f05e4","9a392d1a09","2606a38813","838faa9694","b16166410d","42d043d8d1","b031e74710","dcc761d28d","d94781d8ef","32ac553ac2","b69151825c","604e7f4472","f6b6866cbe","bff35aa7c2","4f082f05e4","9a392d1a09","2606a38813","838faa9694","b16166410d","42d043d8d1","8e541e51c7","22d8280bdb","2e92a87475","2461ecd1f5","c527280185","5fd08a1fb4","73dac127eb","868529b4ce","0ab3010ea2","9cac18e455","8bfd26b10e","8b3fbe6010","9f1ed286f0","136b37affc","bff35aa7c2","4f082f05e4","9a392d1a09","2606a38813","838faa9694","b16166410d","42d043d8d1","d6accf1fe3","6e7f034bd4","6970954369","ad2cd7810e","47b90998b3","64e7fc6865","5b003fa8e7","0391e96ea9","3355e81b72","4ee535f144","c046527dc4","f80ceaec63","4e5beab2a6","3f27be3fbc","0391e96ea9","3355e81b72","4ee535f144","c046527dc4","f80ceaec63","4e5beab2a6","3f27be3fbc","61832d3d0d","acf0055542","46184fe894","0a8414cecc","eb5f82b0cc","30691412a6","eef8461cfe","eb5536fc3b","72eafe7d64","b104b71d39","f338ecce83","4e5976b303","84c092fb14","2e83c04605","eb5536fc3b","72eafe7d64","b104b71d39","f338ecce83","4e5976b303","84c092fb14","2e83c04605","f67bd39883","1d4a623695","5849f5fa69","3b0f9ea2f8","5feed5cb1e","12aaa63ff1","ad951c332d","68f72702ee","0852acb602","045bb45347","af70a88a4e","98ed678999","a0806ae6e1","06ad1b80c5","4623de6fd1","927d6fc813","1167098d87","68e05b669c","93dd9b5ece","626cf7f1d7","c0a5a00908","84a0cc8af3","9efe4ab366","7b82f3d42c","9d3e075d90","c43845df8d","b2b317af24","bb6cce9513","26f0a9c105","55b5c3d2e3","51fee163d6","8c40529415","21f38bbd5d","ce41ba3020","f459ca62e6","84f4cbbfd6","f90b5a661a","0d112b2a2b","0fcccacd8b","ba363d3d3e","be20dfc3f6","aa0b5b3323","82b71d35c0","252e6f2ca7","6b0e6bc311","010161dc43","6beff8496f","9d254891de","2207a54e58","297a86e0bc","6ca33cc897","c569d799f6","e830b21c34","a2eb5028c5","87907e1fa3","1e1d8e54dd","2eab19f222","734c7cc0c7","068d9710d6","f7b571ca11","5918039065","37aee09b6c","39afe78541","68f72702ee","0852acb602","045bb45347","af70a88a4e","98ed678999","a0806ae6e1","06ad1b80c5","94d7b04523","8c4461794d","7c97db5b28","0d0de4a1d3","c96afda784","d473457bdb","d8b67f198e","3c9538b121","ade828aa15","b0bcb93d9a","b67b4a03d0","67d5d9e538","7912e9c023","2eb1cb23b5","98b906d844","0883241e83","4f14c9a47e","ab193cbcb8","ede8de0c45","50840727b4","591200d6eb","b73a54a4c2","43ce8e6c1f","2506d9fb9c","7510dfaa67","602c26576c","6664c4ae8b","c10068ca56","e8d442a316","99250e9ce7","e75e452053","1cf51e4431","fb529ddb6f","89fd215da4","f34faf7fb6","7344afb0e2","be357fe396","43dd3cf11e","50c2c1b900","1bfbd1a62b","a3409aa72b","d766d313f3","7344afb0e2","be357fe396","43dd3cf11e","50c2c1b900","1bfbd1a62b","a3409aa72b","d766d313f3","3facd8c368","a1be05ef34","5258cefa02","d0e2a52f54","948cd66984","01b5fe5afe","f9989f64a9","9aed9afe5a","5430ef3dc5","12076b75e3","343fa60f0a","2b3aa2dda4","a4a0519814","9d1d23027f","8c5474ff38","8f1cacb0a4","330669a90a","bf9506c2e4","20d411beb2","46c1347a50","729642964d","8ad7ebbaec","9f0e34cfe0","e88bae85ba","e6f4933290","c4292828d9","135745951b","f4ff6c7d74","7afb7d4778","ea58ea4e0b","123b1559e3","d5e27b34d5","f24d92ae7d","ac7082cd0b","21f726eb50","27c97e80d0","7c4bcc421a","7fbdc69d13","a2a348c24b","3afea933a4","b5aeaa8e15","7e5156f9b4","525e79723f","2f7620d595","3f973da26a","31ce955212","fadfcb28a1","73eb2bffb1","e22a8375de","525e79723f","2f7620d595","3f973da26a","31ce955212","fadfcb28a1","73eb2bffb1","e22a8375de","5d52ebf2b7","7d5b435e50","65275241e1","5b73db10a8","3dcab00fb7","a9babaf150","650af4b48c","b1eb3e1917","2b80e82794","807bad5dc1","4b2479470c","8053ca1258","4b079f8504","7a312d3d77","2588a0b22c","7549577fa5","5bb129ad1b","2efbf2e140","cc659dc248","c0d0bf7970","8b3b658dc5","1e87b3ff5f","7f38eae169","01efeff6f9","e1c7073977","c27bd7aeea","883751a558","1c5023297c","0b06602ed3","c1fe14204b","70dc779cd2","a859a99054","036b1ec669","9a8f11eb59","f298c10f54","0b06602ed3","c1fe14204b","70dc779cd2","a859a99054","036b1ec669","9a8f11eb59","f298c10f54","7b8265ba22","f785ab0f8a","f97ad30a12","e61652631b","5d9e97aff6","01b277625d","184f094bb0","b2bd9d5d3a","c0c539bf88","dac9191aea","1ea7d91b4a","6c1d18997f","1274af6ee9","805ad774e7","a0a1b58e2c","8447509f61","b10faf065b","eca1accb32","24adaa28b5","387e3c07a8","3df42d41dd","bca2901a71","875a88e99f","8110eb151a","0b799c7cd0","419d0c19a0","28f74d7a12","c1f1446c86","2339983f6c","d8831377fb","3ad4bc6438","c9b6e16f60","9599b7d5ba","f48f2687dc","0ecabfdbef","02afd8ac70","793e65c21e","dd56d48bd3","edb602c13f","7e383dfef4","6fc26866b0","001b95eb60","02afd8ac70","793e65c21e","dd56d48bd3","edb602c13f","7e383dfef4","6fc26866b0","001b95eb60","c1325d78d8","316fc44dab","aa1c4a35cf","a5a8df4a95","a9a8ac25dc","57b713d6c3","2b82425c66","317c0f4320","e6fb6345b7","4d093b2987","d81693aae1","7d0883f892","ee2dd9353c","d999125960","92031f167e","ea7ddc4943","9908604894","cb68ffa3ad","6871b4209a","ea49eb6076","10e6b8c362","d22901af0d","589aa4808c","a5a69b283e","84286d6ef9","4b14e94f50","c7587e8ec9","9f2c5b493d","543376447a","2c9942314d","04d84c166c","597d78fc96","bc879b7b37","ea86d3e00d","936782d2c9","d37ef86f21","cc742fa352","83a6daa06a","3e1001758b","e63e75ba70","6577145662","308f5c3cc8","d282a77d7b","bb7525c1e5","f4e84b3e1b","8c2124d99d","e7732e96ca","9d444b89f9","fede7c9a13","816bea486b","42213ef5ec","5eac2d10e1","f0b011ced9","7f5283d42e","a16089652b","140fbb85e6","f34d5a9e78","63d9b2d239","29bd524535","68c044375d","ee2af71a19","0b8ec42776","e921340997","5e92ba9062","e95705dd3d","bd9844d647","1a0b462b28","4507428cd3","1ef063fb65","e58a6ba88c","5e92ba9062","e95705dd3d","bd9844d647","1a0b462b28","4507428cd3","1ef063fb65","e58a6ba88c","14a4ff27f3","7600c00e08","069fa64bef","afc3df0e2b","8c53a288dc","3277dcc30d","c45871b0e3","ee4b25164f","2edc7f18f8","7adc24893e","6dccc81750","4df3bd71c9","354c98d86f","8f4c1b7780","92031f167e","ea7ddc4943","9908604894","cb68ffa3ad","6871b4209a","ea49eb6076","10e6b8c362","b8ce17127e","e19c266e39","9ed0703d1f","7d91828b77","3f01393477","aa24e09f7f","7b721c2da3","b8ce17127e","e19c266e39","9ed0703d1f","7d91828b77","3f01393477","aa24e09f7f","7b721c2da3","1dddb872a8","fd6d67b661","0b15f51ca7","374555c4bb","ce39ab61e2","2e442abc45","ba5d2ff534","1dddb872a8","fd6d67b661","0b15f51ca7","374555c4bb","ce39ab61e2","2e442abc45","ba5d2ff534","06e8e2e813","a35222c35a","e59230718e","cc13eae474","4c3ccd09cf","d9617ffae0","931148b31e","75308db2a0","9d97ced9de","a5fd7a02ca","98174e133b","7e29a25b96","3f7c539726","1dd9200bbe","ba9f524b9c","82b7655925","62201cbaff","a1bae83341","1d59c66386","9c765f8862","9c4491c4ec","2c2b77644c","00651f9d02","856aa3749e","48a4dedc8b","9d1b55108d","2bfee4aebe","cb7e93a30f","683ca40538","f77eba39da","908614832e","5c89efa5a9","87770b420f","0904972448","c776c017b9","8299bf602a","0a70f0676f","1059532242","18fc8bea8a","2f95e0f8ee","b7ecd36531","6aa291d4d0","0802c9d71a","f74399e7d6","9a0a1346ca","f41b36f636","ee94d0ae17","a37e8097e4","d97ed226a0","ffa24fefc7","52eea714d2","3d3b8d0a11","d20849bffb","2461e41e89","fae4163215","a55a8f5723","8e5c89d0a3","86cc30abf6","b0178bf7f5","fac3f60b39","061fe692cb","5c56280d3f","3ccc2286e4","78741b4c7b","baed57315c","ab1a7bfc1f","06ea41a908","f2eea51023","83b88eab1c","e47ddda07a","ba9f524b9c","82b7655925","62201cbaff","a1bae83341","1d59c66386","9c765f8862","9c4491c4ec","ea43ac5602","a418187876","2827fde6f1","755941518c","2d52b67f80","3283d138af","57418184e6","ea43ac5602","a418187876","2827fde6f1","755941518c","2d52b67f80","3283d138af","57418184e6","b0250e03c6","a2a4ba0dae","f17f4e913d","9d796826c4","d2392a5ab4","e424149b53","4854146d11","ee61177782","7efaf92ce4","96a57b3f4c","28a553da75","f64ecd72ac","e5fb7dc209","4beb47f5ec","1fe31d735e","478de0943f","b961c1e429","a30da21561","902ec7839c","ac4fe4c059","f183026eb0","ee61177782","7efaf92ce4","96a57b3f4c","28a553da75","f64ecd72ac","e5fb7dc209","4beb47f5ec","aa752cbc5e","5d23dac633","7420ea9e93","04e8103ec3","0d28e93497","3dbe6d82e4","b91251bd60","d2ea887116","b57f82a994","b0804611a7","d8be9c193b","450e202b2d","d8ced34153","ad2c3f6281","473fa7b2d2","74b8e67ca5","03c8745efd","17dac83406","8b2da2b019","c244a92b39","0c12b1f74f","3e9e776105","dd53b6d45c","5ea0612b89","676ed2ee3c","25c0fe3b40","39932d7451","db35599d22","41e2e7dcc9","ca8539f455","937da822c8","930b54d219","d932ef6754","fced85f0be","f7f1e5c768","d2ea887116","b57f82a994","b0804611a7","d8be9c193b","450e202b2d","d8ced34153","ad2c3f6281","d2ea887116","b57f82a994","b0804611a7","d8be9c193b","450e202b2d","d8ced34153","ad2c3f6281","5c96eb1a27","5982dc542e","e5c38fbd44","5969ef134b","43c7a86036","e9676aebfa","2b9a2bc7f1","96f552c545","4cf661b519","06bdca46cc","59f460416a","2c50dab35c","afb41dd5f8","11668e0f55","c9c3899d46","5f80a13d24","da801348e5","172d0b64ac","217ecbce27","28dbe4cab8","9b09ace382","8f89afcad2","31ad7b74e7","5869ffacec","1daed722ed","facf2fbb9f","a496625d41","7bfe251591","26e5f50357","7d978d0b05","4645c61f44","30f44672a3","f6754f3770","c48a593cf9","6ccb527883","8f89afcad2","31ad7b74e7","5869ffacec","1daed722ed","facf2fbb9f","a496625d41","7bfe251591","9f09234327","f7022ac8ad","8ab5aa1980","8a730fb62d","a2f472dc3b","2a905b20a3","6136ff100f","6106c7e4fc","3ab5ca4662","40e8c5d16d","42b1c58517","bfc6c7ed05","c50b543494","9086e9dc52","6106c7e4fc","3ab5ca4662","40e8c5d16d","42b1c58517","bfc6c7ed05","c50b543494","9086e9dc52","9e39b83721","06d7b9b53c","8262f8bb7e","a67223d956","1b6059e00e","873e5f915e","6a0df4ca1f","2a2ccb5f06","d5b06e8bdb","838d592791","5c7f371ba2","c622fb31e0","b7c471a283","41b1b46c96","2a2ccb5f06","d5b06e8bdb","838d592791","5c7f371ba2","c622fb31e0","b7c471a283","41b1b46c96","ce5577a6fb","2166bf9dc2","866603eef8","637b4016b1","2d759f4e30","1f8fa53c0a","1f4cfc66af","747cc73cad","06f763c6f6","fae4f2df3b","e7ffb99293","5aace269b1","baad47f7e0","7d797a2de3","85cea0d089","eb8689915e","0addf269a4","a57445329f","abc6c440e9","62283e737a","f37e92a083","b219c59d84","fe673b07cf","333fb2a50a","c3743ca7a7","eee03e5a98","54b21b2497","fddb6bd3a5","85cea0d089","eb8689915e","0addf269a4","a57445329f","abc6c440e9","62283e737a","f37e92a083","0563e2e5ab","df8982660a","37c74e0efd","1067a271b2","b0c8e1bcb9","9db34fd6e4","7b22a81995","23a66dbe7d","3a0dd1b8b2","a60a197c8c","725c4e7d7e","f91ba02632","25fd5aade6","269d132f7e","23a66dbe7d","3a0dd1b8b2","a60a197c8c","725c4e7d7e","f91ba02632","25fd5aade6","269d132f7e","7f8b06b13d","1e3339df5e","a3cbc1e9d1","baa32554b2","7c7b6d76d0","ba845a4645","5067f723d5","31589b82fb","b397b3d91f","7de4a4c9a6","d2630f3544","08ec7b7bb7","bfdd35dd3a","8ea4357ba1","31589b82fb","b397b3d91f","7de4a4c9a6","d2630f3544","08ec7b7bb7","bfdd35dd3a","8ea4357ba1","493908fe67","05a026fe20","d963ff229f","f9e2705c8f","6b6a22d847","33ee247266","a832392d01","75bdad1923","62164606ab","8582ecb2e9","091fda4954","84fc9be709","c0d76e22ae","2bc4149c78","3a661bbbe9","d63268b607","caf7b733de","1a3f2ea34e","633cf63ccb","dcf8bd82af","ea26b57873","e16b191d11","ce4986b2ed","e784eaba2a","08b66dbfff","7880249e1d","645187c425","54c2d00cf9","3a661bbbe9","d63268b607","caf7b733de","1a3f2ea34e","633cf63ccb","dcf8bd82af","ea26b57873","ce3c227158","b383a9185a","3a15e48b42","6e69d47dcd","1f86652cb4","4d3d931d3a","0385e3e188","3a661bbbe9","d63268b607","caf7b733de","1a3f2ea34e","633cf63ccb","dcf8bd82af","ea26b57873","8ab451fd50","9b34dbc061","06ff8d7d1e","26c4271728","92ca60650a","930968a9ec","86325cff64","e3d7f3f468","149e8f3545","bc314ae0c4","20c50e94fd","c58c1c9578","73b1701e15","be501b1e63","ef755107be","ede08d108e","1cb6634de5","66bf1e46e2","679ad4c32d","6d2c1dfb45","c45cebf373","b7a844b873","522e63cfa0","89ffbdb6a9","9ae31f6bef","d85698bdf1","4f3a5b9938","8991c83c8a","5282a1c671","aa7fa022bd","9fd9ff7c14","4601cefa1d","ea4f469545","30e6dc1ae0","951d88c215","5282a1c671","aa7fa022bd","9fd9ff7c14","4601cefa1d","ea4f469545","30e6dc1ae0","951d88c215","cf146a7ab2","5dd4e9d2d9","c7294d2a4c","684f13cd82","1ce3876682","09e7759585","6890502f26","cf146a7ab2","5dd4e9d2d9","c7294d2a4c","684f13cd82","1ce3876682","09e7759585","6890502f26","f08c5623a4","47763fa437","9ec745def5","03ad2b667c","da97f81c9a","db302567aa","78a0268226","91cc93e997","ba44099fde","29b637eb9c","cf60731b98","7ba06a84b5","136863046d","28e4f5fb85","e4b726a12a","a4c68bfe34","aeaa1f0bfe","a940818909","12880f3eed","9b6c54adbf","7a42cc7ed2","edfe1ac993","574f25f7b0","94fe38687e","e39b2ad002","ffb7bd0275","e86ad9b4f5","643ef91a09","c76af9e48a","381d58730e","9302522dc5","481e9efc24","5a3c6ea27b","ae63a24aec","f7c71389e4","954c125c1c","8af26ea7d4","cac24a348c","29f2aa59b3","d4a74ca974","f7f9508200","24533ca77c","c76af9e48a","381d58730e","9302522dc5","481e9efc24","5a3c6ea27b","ae63a24aec","f7c71389e4","93be7b3caa","0e1aff3ddd","6bf2e6d596","184e4215dd","c5d94d16f5","a3beab9bd7","3243096999","9610a824c8","4f84450698","7f42c0e29d","0420044b89","ba781f9c3b","71f8124ac6","1a4c987ffb","9b4098d83d","22b3e7eeff","41f4b22aaa","8c1e5e79cf","c640a923bf","31cc29dee4","1f37e98630","9610a824c8","4f84450698","7f42c0e29d","0420044b89","ba781f9c3b","71f8124ac6","1a4c987ffb","521812e193","288e30eb37","09c3570812","f3229f854e","23ad483fc8","e4a6243cd9","504911d7e3","59900c1e61","743dc73b16","9948cdce3d","3c9280b353","82a03fd5f2","f14523c8df","40defa0841","2ab1ad1d80","54800df06e","e765a3ead5","b122aee8f5","492701cd68","ff864f2550","bac4b295cd","2ab1ad1d80","54800df06e","e765a3ead5","b122aee8f5","492701cd68","ff864f2550","bac4b295cd","b58558a94d","9a0d6fa153","8193a00c7f","a8a30a4424","e2e3019367","ba5b72e93f","fa01b43218","b58558a94d","9a0d6fa153","8193a00c7f","a8a30a4424","e2e3019367","ba5b72e93f","fa01b43218","77bbccb7a2","a3b1de2341","dc58fe7b34","1b1cea8245","c1ded499a5","be9403b589","b6d327da2d","805dcb4bb4","c6eef97c70","883919080d","e1ab2b5b04","79602d9a36","27dc6af88c","85663e00ed","805dcb4bb4","c6eef97c70","883919080d","e1ab2b5b04","79602d9a36","27dc6af88c","85663e00ed","878c6e8422","761a898597","18bf4eb7ba","1c9effddd2","595cc6b3ec","7e63928c9f","e36a02f449","ac91fa6456","b075912807","74686818a1","c8e3e2995c","7fd9f0c6ca","a8036a8204","4f7a5534ed","382e5b975d","3639088d3a","dae64eb3aa","2e75dd9461","7bcf977e98","5871e8cccc","1938321931","081e90d1ef","a1dc400680","d6d39a339f","f39ced23f1","8b9c2a5a8f","53df8dc888","728641c704","79fe08f9a7","5123df790e","a6f5aaf3d3","f78a38b08b","71dc760200","7186e1c4b0","ff037a4b30","0e45b5c505","b9bfc6eb81","96fa71308f","71474bf2b0","3774bd5faa","e22cd8949f","3e1f82566b","6a700d4c68","3a2583dbc7","b124357fd0","dbffe91383","9de827a4cc","553bea032d","8ecb386302","878c6e8422","761a898597","18bf4eb7ba","1c9effddd2","595cc6b3ec","7e63928c9f","e36a02f449","43b8907d1c","2f01804d83","8d4133793c","cf2997e89d","3e27c9efab","bf981c9132","3d1fbda4af","a22aa37d5b","7e59e3655d","0401af2eab","2c0d0cbbac","aa8dd80609","f1606d9bc9","8221d1c17d","78d6480783","4dc1877ea5","2b379b3cc5","def98ced32","6c06361279","fb155b56e0","84e4671f28","0a11d60150","2f7d867ff4","9fd4936e05","fe8dee399a","0302311b0b","63b90de36d","d073d6f498","4ed0fd226c","c1648bf635","1ffedd866f","533d144dc1","8e80e8d82a","65f4271478","434d2924d8","3861a31292","c68e1ba9ff","042c050653","1f93eb9094","033468f9b0","011496c3d2","ca12d9fc3a","3dd369788e","64cbb38769","daef3c30fd","cab5fa630f","78481f0725","6f3f35f391","dd4e69ea2b","78d4804687","82db449099","37ac78665d","4423431f7b","2eaeb97f8d","5371f47b27","731ea5b7e2","78d6480783","4dc1877ea5","2b379b3cc5","def98ced32","6c06361279","fb155b56e0","84e4671f28","e0a774e6ac","3e6f1629ea","1aa5a665f1","db550d5adb","f2687f816c","02b78e465e","cc92f23818","4335f06e93","1f43f8d40e","d448c156e1","61b507f1a3","785e8b8734","d03d919eb0","479e271403","7b88787887","3f3d4b97e6","fab12ef62e","0d889a2cc5","77cc983fcf","4b886100fa","a59a184dad","e817d6bf5d","4747b54340","a21ba531da","f414531ba7","563a0ccbbf","ae66997be1","dfda964ddc","db1e1c8ddf","f68a41be30","f560a7d011","8ac0a6778d","59e6c29e27","2aed3f783d","6ce60c17b2","cf56a4132a","7807743f87","acd0aa888d","9904566c81","cf438987be","4637bc8828","69ca019a40","cf56a4132a","7807743f87","acd0aa888d","9904566c81","cf438987be","4637bc8828","69ca019a40","8572075f01","fff0c8b4eb","879d3985c7","05dcdca415","80c8a5d00b","fdf2f88508","370b03afd5","b3d1787d9b","0f945062c4","7df80e158a","c5bdb676bc","6715246bc9","ce506c16be","6105213dce","a51a18d986","a31bb8d32f","b20264fa90","b2c82375d7","7109722d5d","a51a6c2ef0","8ea4d9a375","5c68d86d1d","3a5255e440","f02df54820","f51a719331","a3bb9a7067","e7e0d90b3c","3ebfccaf48","378783f0d5","9285f1929c","5a9965af57","bd329d5752","084bf569a6","537abbd85a","905d31682b","43aa53cf19","ab3c78e806","3716ce5a0f","5e2d1c3099","f0f4cf0e89","f526aa3408","dbd02c14d3","a51a18d986","a31bb8d32f","b20264fa90","b2c82375d7","7109722d5d","a51a6c2ef0","8ea4d9a375","440a0dc4e2","931414a4f9","ad2a859abe","602efc629d","277085cffd","510193884a","0799e75e89","87c147ff69","3909540f69","99918b6e35","8e21ec5c7e","7c3f9b2a09","f69d846c85","e1d85eb477","bae0bd386e","6b84432391","bea07c5c1b","807ec73ebb","17ae2bbdcb","b468c6b60c","d17fe035d0","1c8d9f3715","e6d2aeb543","73da9a2a7e","63328dfcfa","d547dfda7e","111ecb51d1","51a9727659","10d89cf27a","51fb94ca3e","5d4f57269b","fb8812a3fc","5ed068c025","0be744e1fb","4171982b2a","10d89cf27a","51fb94ca3e","5d4f57269b","fb8812a3fc","5ed068c025","0be744e1fb","4171982b2a","f2b4f49f5b","3b9c446b38","e550e1f42f","ae928b83d1","6f5eb9ae4f","9e62b59302","a14654a975","f2b4f49f5b","3b9c446b38","e550e1f42f","ae928b83d1","6f5eb9ae4f","9e62b59302","a14654a975","cdc081ed4f","ef96c45285","1604ba6ca3","3bd090bf0b","61742ce575","d48132da46","ca459c1c89","8f58b9c67b","9c41e784f2","8610d94832","78882407e7","ecb81437a1","4bf1bf24be","ebd54f27e7","95274eedde","79aeb33b0b","6a27ac4afe","99d35ad57c","9eff8009e1","cf2b895ee8","c985dfbfcd","60b0a7f706","5a96ef4290","4bf20ae235","28b3f9204d","c06379849f","2a9b33ad07","75a5c75a38","c4fc51ab96","46d882c00d","adca2291ea","b61b9b0c2b","3a6bd36f7a","49439788c0","7984282c79","4a8372801a","091dfcaf55","5beeae9a1d","cc193f49d2","8cb3a7944d","841149bd74","3226dddcce","72e0d53d79","1edb0d246c","b5a66c48d6","4c218f34e5","13ae965d14","4af94990ef","beb99259b4","72e0d53d79","1edb0d246c","b5a66c48d6","4c218f34e5","13ae965d14","4af94990ef","beb99259b4","fcd27d41c0","5c3450f039","6265fc042e","b3a57902bb","2385a91fc3","d557f978fa","b77d17d73a","61e8525313","84f3a36c87","b7199000d6","e5e9c025d3","4bd4c93c37","be9eaf0374","b907d8cd15","495be88f66","aaf95903de","7d7f6bce60","e31ca33edd","cf4d64c077","6a5c5d6ad7","4992196ad6","04a8682843","426da3c8b8","7eb4b948f9","1d5a7b759e","358dce80b9","85df8fbd73","90c883d829","61e8525313","84f3a36c87","b7199000d6","e5e9c025d3","4bd4c93c37","be9eaf0374","b907d8cd15","128f1907d7","76da2fe954","390d63abc4","75e63da65b","d763062d7e","8eadffc2eb","349aa61edb","058ff92e17","2c7b87ed19","aa79154993","b23061f263","cdb13d11dd","d7572a3173","0e36c8b49d","058ff92e17","2c7b87ed19","aa79154993","b23061f263","cdb13d11dd","d7572a3173","0e36c8b49d","528566862e","dbfda0a198","19de277257","1e3fdc154d","b93be2ebe5","b46a352966","79b52bb81a","bacf770e7b","810bf519eb","8af6c2b5ea","192cbeb006","d682b79992","ba094fc348","c66afee476","78d4cc89db","4ac077c4fa","340d65eb7d","887b93800e","8f683e6a22","3d578b23fc","043a869dc4","0444cd1a2b","bffe1ecb9f","e6cdf9b610","ddeb164134","ca7297befb","a508ae05c9","3da3c05307","49ada2cf28","b5e6af4af7","feb9787dda","dfa50cb054","9835db886b","445e46cac7","7af356431b","f525bc907f","dc607830a6","32e7458b4d","dd725195c7","249e030925","a8278b07f1","3e9d93b647","d97a9d1631","41a499b862","a7d6d6e987","7b27ffebaa","7307851702","3ed4919b8b","e1f350a861","339e6066e9","6b67c845ca","7d7267b025","afa0005ca8","5badc99b1f","f3a00a0be4","251026e7e8","c82d307f84","b2f90892e6","306b2c2c4a","d19b31bcbe","1fd58b1f2f","45252b1a01","f478dc004e","bacf770e7b","810bf519eb","8af6c2b5ea","192cbeb006","d682b79992","ba094fc348","c66afee476","08b0c283c7","8245435d83","f24bb0890f","ecbff6777c","e4ef09bd73","5e3f5cccc8","5e9b48d026","403d4f9235","49a96ddbd4","94afd417bb","2bb553ea2f","81c576af49","bb1d873b82","eba4e29655","403d4f9235","49a96ddbd4","94afd417bb","2bb553ea2f","81c576af49","bb1d873b82","eba4e29655","85121189e9","88c48408c4","05c3b2c553","f829b6a852","70772f455d","2aac68eeb6","057bd2aa85","85121189e9","88c48408c4","05c3b2c553","f829b6a852","70772f455d","2aac68eeb6","057bd2aa85","1b82b51259","4f6718ab55","1bd2cad1db","1fdc56db76","ef45d01213","ebd7e9cd89","7c466d32a6","1b82b51259","4f6718ab55","1bd2cad1db","1fdc56db76","ef45d01213","ebd7e9cd89","7c466d32a6","0da8dec35e","34373b8891","310d1ff891","4881d965a6","802ff62f46","8c1a8f5bef","1cce22beaf","4b8c35dff5","ceeb3a6bdc","6d98d42fa9","4b3cabe33e","b74c2c319b","bf69b937e8","9dee837720","9ce130b6c2","7ae446bb44","b16cd7f1b3","795d39e33a","0c78364ee1","1daadd97c7","4f5869b632","bbdc111447","fe23d41f82","2cbe55b668","288dce2e6a","b2580762ac","bc92df6880","0e21e4fc8d","8179cfbafe","7e231f0629","3f7565626b","2044feaf2d","2c1cf07041","84aa4cde79","0cd61545d5","2c17100d3f","33ddc75b7f","3de207dfd2","e1b1d72940","e7a561411c","de4645a76f","1b16f09ab2","ca77a87625","fe8dd14f83","eb6786f517","e8285b80d7","2e4998b25c","8e19c8cbd7","652ccc48c5","0d08b009d2","76105ac48b","2f4ee14bdc","858f6e285d","81fb4356c8","332ee1befe","41cad305d5","434ef60b39","7c10bb3829","80c7f95909","86e12f8e99","1ed9274923","3ea95d2695","99db1200aa","500031dbfa","e09e5ea77d","0573ca6428","b4c53f5485","b14af9a48f","793e3dc415","0f331de93e","500031dbfa","e09e5ea77d","0573ca6428","b4c53f5485","b14af9a48f","793e3dc415","0f331de93e","5ae3769a9f","1ee41b5713","e0cada830f","8c13645120","f171bc273b","983a1462b2","5e7f939086","c71305103f","27db09a569","e89a14c641","e33e721190","0cb523b09d","d6547af96b","7939648041","c71305103f","27db09a569","e89a14c641","e33e721190","0cb523b09d","d6547af96b","7939648041","81fc31d061","19295b6fed","abc99001b8","8d2b717958","cfd28208b1","7f630a7719","4157fbf6aa","2b1224c401","2e9686c1f4","67a86bf8a3","22d2133d44","0b26a11f08","5854a7ae55","1f19c4171f","2cdf0b9c73","4721f3456f","2ce3d7f8db","9bf644454d","96471cbcac","1bbc0c921f","433dc2cac6","eae9459cab","262641aa56","3e566a7cff","7305a14a04","579c10a26e","2e5643eb32","05ea8311f0","2c4e6d2c94","2631994b79","07cee20558","f6795cea69","124f7ff48c","ebe2639c38","03b47ce7cf","916b07f70c","ae57415024","96e22707a2","8552386f1e","2a8dbb7138","3a3db5d676","9ef97b89f3","81fc31d061","19295b6fed","abc99001b8","8d2b717958","cfd28208b1","7f630a7719","4157fbf6aa","81fc31d061","19295b6fed","abc99001b8","8d2b717958","cfd28208b1","7f630a7719","4157fbf6aa","6a6cd48a26","1ec0249c2c","27d4a19cfe","dc86350044","420b580a60","be1e49384b","dd380a0c62","f626bd6715","41224de34b","1fdfbdc602","b76d6ebcfa","8d9aa6a522","afb1e84839","4a77266307","f626bd6715","41224de34b","1fdfbdc602","b76d6ebcfa","8d9aa6a522","afb1e84839","4a77266307","316ffcd8e2","1369c73b6a","8f708a8ba0","353b77fdc4","5c1c220436","87836f394a","0581a30072","d1b6be7513","599c8bb442","bc3d5f924b","e3812e8930","cdbea1ccc4","5dd73c225b","01f975e69d","9000795d88","b40fb586ab","1cc13d5ef8","2cafd55604","3e1313e1f9","f995de6ee3","dee591f3e6","aebc351264","6a81ce2f19","a93a81956c","22c17fa3c5","bb2c19f009","3095d161fa","797da98306","9000795d88","b40fb586ab","1cc13d5ef8","2cafd55604","3e1313e1f9","f995de6ee3","dee591f3e6","2eb3cf9b45","e814d1d37c","3723931408","c310670487","396988fc35","cc747b151b","7055e1c8ce","bd818ea578","ad50c85b1f","b88edacf2d","bb661a8419","4a969d80b9","a6bd5219f7","fa741f7b40","bd818ea578","ad50c85b1f","b88edacf2d","bb661a8419","4a969d80b9","a6bd5219f7","fa741f7b40","80568508bb","cb1b71a92d","f910a252bb","a151ec1165","a0ff584e7f","00b0eefc53","62033514a6","737198857b","9b9d706978","09ebda33c3","192c34fcc3","9a7dd500d0","6243bcb679","54aa57a1ab","bd02b04f52","24e489acff","b4c7316d7f","c78d43929a","783cf59ff2","d03c283cb2","a71dceadb7","ee023af14f","9f2fe55e2e","ca378fc62c","dee616766a","e6ff8b760e","66a20edfdf","39f3fbbee5","4026788293","86d2d74147","8c0918ab98","ce1bee3ab8","45627d5107","a5743c0c10","16f8ba715c","dcd7f64a7b","eaafd637eb","6fb5b89f65","816d4b4fee","5f1b658ca1","2ec3980a0f","b594d8d826","6949f4d300","0d33916887","42555b8a18","4098605d5d","8b915fc855","0b04496776","9fcf34779e","6949f4d300","0d33916887","42555b8a18","4098605d5d","8b915fc855","0b04496776","9fcf34779e","63481bad40","86f09a0af8","c6c1047748","c1b482deb2","be2756f11a","295ff599c0","ee9bea7d06","2d62c326cd","23553b375f","92ba43275d","80efa5bb79","412ce6e44b","2b5339548c","58ddc6c24e","f1b5e3c207","70e9673e7e","409b706fd8","faec8a19fd","67d4e89c1b","da896e19d2","65a5f9b909","f1b5e3c207","70e9673e7e","409b706fd8","faec8a19fd","67d4e89c1b","da896e19d2","65a5f9b909","5a0fd88278","f6cbaec4f9","6b87f1d3b9","80f016b177","0729d5829b","c2ebf84328","a6e7e1b55d","f5738eb8e0","86b036e2cf","0053a78c16","05d82b5c01","418e1cf694","d5d83672d9","939ff2836b","c4b7101dd7","b2cdc8659d","810c294da8","02451b9f2d","4ec7140446","a9b62383ba","9aeac3a6cf","a531f60ebf","2a91e43413","f60f14ec73","97426d316c","885feb984c","65977a0de8","7dba25aa1f","d52dbb9617","0fb6eb45bd","c67095fb71","ffa5c21bdf","d7a66492ba","0a64e62808","45c42388cc","0f2e229f3c","6a32225f3c","929d88d48d","8e75eeafce","954e13452c","85732fb46f","2aa7520cd2","618acba346","e2716a1614","3710b1dfa4","0cd51ee0be","9cb24bdff8","b832edb5fc","b99bf3abc5","16a365369d","ddcbc578aa","cf7a71ff36","6d3f1384cd","689f15063d","7e9b3a030f","a4f0ec602f","16a365369d","ddcbc578aa","cf7a71ff36","6d3f1384cd","689f15063d","7e9b3a030f","a4f0ec602f","e65d0d08c1","55e09cd152","deb9e8d8f2","f06ebd60f5","8c565b5be5","d078d5835b","518431da47","2d6089dcee","b5928d8ba1","999d01bf42","294b981972","7b9370ca09","904d4cc007","ffd5a1e598","979a7163b1","bcdda2af15","6f90060c3e","b1c3815895","315f7b031b","1cebf46114","63e1a6a649","8e9ea0d774","fcf282b113","a1695e1c89","4a2c511720","867b6d0d9c","0e543b5e9b","0dd2d379eb","9f1d1eb95c","2f3dbfe99d","317914b69c","bc98427c34","a35041bf0f","891df60eab","6ecdef40f3","8e9ea0d774","fcf282b113","a1695e1c89","4a2c511720","867b6d0d9c","0e543b5e9b","0dd2d379eb","8e9ea0d774","fcf282b113","a1695e1c89","4a2c511720","867b6d0d9c","0e543b5e9b","0dd2d379eb","ddff8aba4a","053a5c177e","cdfbe2dd0c","1207ac8dcc","0c8da7bda2","be1368942e","36ba097b2b","ddff8aba4a","053a5c177e","cdfbe2dd0c","1207ac8dcc","0c8da7bda2","be1368942e","36ba097b2b","d33b82b778","1c8c1c150a","43cbbe2f0d","6d5fbeca0f","7f9c8e59ab","9f0306c067","d4e7664389","d33b82b778","1c8c1c150a","43cbbe2f0d","6d5fbeca0f","7f9c8e59ab","9f0306c067","d4e7664389","523d1d8f8e","ab63cb5acc","ff489679f3","2a1078a88c","665b96b61e","ff5cb10822","07487d10c5","523d1d8f8e","ab63cb5acc","ff489679f3","2a1078a88c","665b96b61e","ff5cb10822","07487d10c5","6113a64c0f","60c5c5d128","87d0470196","005eedfaae","b7b0fb8b80","481ac6fec8","679f4c9ed0","6113a64c0f","60c5c5d128","87d0470196","005eedfaae","b7b0fb8b80","481ac6fec8","679f4c9ed0","79f6ff86a4","b8de0d83bf","0486ee8958","12ebeb0d62","155c0de22c","cc02f6ba28","54403e60d3","4e6931c087","654eafc267","aaec2ec1b8","404e6a5eb9","f55df685ea","cfa44e5431","4970271a67","97fa3c7731","5a56ea9e0b","5d8597c355","3ba3a53b50","0cb766b79d","980905dd71","2aeb018bb5","59d9d7cead","85953ca554","9306a9ea78","fa18406efb","b72b095074","ac24629a01","40c98936e1","59d9d7cead","85953ca554","9306a9ea78","fa18406efb","b72b095074","ac24629a01","40c98936e1","6c077e9668","9dde716031","435f6492d7","bc46a5d6da","60a3cbe6de","c9d6b3f522","7b60f02d69","0ba82552fa","2e47554000","c1ff50aee9","54eb8ec0b5","4023fd9489","54e0af7bbb","9f89b20c27","0ba82552fa","2e47554000","c1ff50aee9","54eb8ec0b5","4023fd9489","54e0af7bbb","9f89b20c27","5294109ed5","6723442dcf","7c969876ae","9f2549b09a","4efe289f37","8687ccbd22","8327e5f7f1","5294109ed5","6723442dcf","7c969876ae","9f2549b09a","4efe289f37","8687ccbd22","8327e5f7f1","c4b63778e2","b30a351630","49349b0f04","2e918afe6b","7095d88dec","f99654365b","d6da2a3416","c4b63778e2","b30a351630","49349b0f04","2e918afe6b","7095d88dec","f99654365b","d6da2a3416","cab5e120be","801afc5931","38b888971f","faaf75672b","95929cba25","cdefa6f1e0","646f6685c6","d46b1d1fab","9adbb9e836","aca717fff9","d7af30518c","a12b7b6635","6338c02e20","b196587dd5","5c316361ba","b97c525c8c","6568f3d968","63eed97dd3","78c02d3b1d","bd5d4b7f74","3ae173653b","5c316361ba","b97c525c8c","6568f3d968","63eed97dd3","78c02d3b1d","bd5d4b7f74","3ae173653b","c4b63778e2","b30a351630","49349b0f04","2e918afe6b","7095d88dec","f99654365b","d6da2a3416","da6db38b1d","8920f55951","0a2596a91a","dbcf3f7969","6b9aa2e384","11a2d17a2c","be291f25a6","5d530359af","4907c85565","beeb1babd8","b31c771565","e043bcef35","92035871a3","2d18718384","dc94bac0f3","be29324259","4239920113","210902b9ac","84193c8aed","fbdae19bcd","39afa0a440","dc94bac0f3","be29324259","4239920113","210902b9ac","84193c8aed","fbdae19bcd","39afa0a440","4551506c6c","7590bf7e7f","d0e144da8a","6c7b736f6c","c1662b04ab","da231d6ddc","d47d0c1a61","d0b549ab39","aa359b3f38","f2f9610494","e6f15a90bf","b23a32b15a","cf78e0c9b3","814dc6886d","d0b549ab39","aa359b3f38","f2f9610494","e6f15a90bf","b23a32b15a","cf78e0c9b3","814dc6886d","d0b549ab39","aa359b3f38","f2f9610494","e6f15a90bf","b23a32b15a","cf78e0c9b3","814dc6886d","6e25a5d9fb","be69ab90f1","5e7c6fff0c","6ea451f84a","9efa9ac4b2","f5bad0d67e","14f0744476","ccb8cb7ed3","31b2e9eaed","55a446cf6b","dd322cac46","1075264c4f","0b1c4bcd02","413fe93bec","ed89e0dd99","871213237a","2bd5a26856","f28735e369","67a0d019bf","6b7b5de11d","1623ade609","64b7b43ef5","b28620bb29","3d6c3a7291","0b32852559","dc212cb297","60631d270b","8b92dd4e22","64b7b43ef5","b28620bb29","3d6c3a7291","0b32852559","dc212cb297","60631d270b","8b92dd4e22","4c5a6b09be","dce34204d6","2b687fef83","f884b1175c","00d18bf015","75a13d37da","8afdb1463d","fc125097bf","612b5b8cd0","d27a2ad79c","7f30a4e07b","46c232dc9b","f793b5fedc","4a676133d5","832f8cc144","adedaccbe0","6320ad6e43","8d8c488f63","694b49b8d5","85028a215d","a86a08f8d8","8aaa48c814","798de9cd52","9c4ccbf3f8","17c86decc1","0a9e842c4c","8b663ec171","8c49ac57b0","5c41ef6d21","96325acb0e","2f6b3ae30d","ade6dfa218","cf5ca4001c","074655b335","bd442a8da7","5c41ef6d21","96325acb0e","2f6b3ae30d","ade6dfa218","cf5ca4001c","074655b335","bd442a8da7","0d1d1d307f","e70120da49","36d733cebb","cc3df29478","0c17c45324","8d3f4bb20b","cc16a37bd5","d1cfccb031","084de0c736","7803120bf2","03539cc4af","e3851abf86","0275158821","941a8ed88a","821a851044","c82c4eac51","8ad74aca66","86cb45d4fa","32a934c2b8","189371ae69","128933f984","863b9e9cdc","8c03e4a74d","2d86811008","2e4455483c","b248e77ad7","ea25714b8c","25eb25b261","f7bc05e032","a8b8eeab9e","0217815daa","c5183819ad","a5e639c973","9b95868520","f22285a60f","863b9e9cdc","8c03e4a74d","2d86811008","2e4455483c","b248e77ad7","ea25714b8c","25eb25b261","4b7ada454a","fea057cc78","e59108abf4","e1dc48bf83","4d9cdb9b9e","303eb3db46","7bda51d656","745d8e67a1","d620a43c5e","3e83fb76e2","6c32f25b9d","0a7a23803f","26bb789bea","d79d3f4eba","73c7308c59","824bfb0178","eaed448b65","f192ccd27e","400f8768d8","aeaa47d938","2d255fbe44","702f541877","fd9ef00c5f","486c51b30a","7b6be363bd","0f10f7ba8a","b7ffa89665","ca08d0e3b5","702f541877","fd9ef00c5f","486c51b30a","7b6be363bd","0f10f7ba8a","b7ffa89665","ca08d0e3b5","e344f08131","7d7f45d473","a7c01aa9d8","70f3b819a0","1dd4dccbee","ddfad5adbd","ec34a8473b","1d8b130c33","6ecde19b0c","3e62801295","dede4e6d36","78304f8832","57c6243099","f8e465487e","e441e3b8fe","3f082afa4c","f7de4f4826","c0a56499c4","8a944f06de","db070c9cb8","4265fda71e","106927df39","ad5b210278","279e45f683","04830a9508","f3a6143432","35fc8f664b","4a5dd7292d","17016d69d8","5b80b5dbc1","25be41c13d","76f5d5d95b","fef33f68e8","4a80a5f99c","5d1c0006fa","17016d69d8","5b80b5dbc1","25be41c13d","76f5d5d95b","fef33f68e8","4a80a5f99c","5d1c0006fa","d4e8f7a0b1","b9f4b5d70c","755d4c3c72","2ef9bb12f4","5e79cf7431","60e58229f7","8f724ca4af","c58125f469","026134e5dd","ed2ec60d76","cb1c545ab5","11db0c7936","f3e8bde552","1bbfa863f1","c58125f469","026134e5dd","ed2ec60d76","cb1c545ab5","11db0c7936","f3e8bde552","1bbfa863f1","ef86ce4999","1f3f483bc4","fc13a3e734","d344d55778","b5dc6ec337","cf934df2db","0e1ed89e83","f8d6b9cc2e","67f7b82bb8","7f5837eaf6","44adc26f14","1068e945d9","de59c9179c","14e3b22aaf","3c6723ac17","59bd581e72","0ad7abe0ec","4a0277d279","5437f125ba","a022463708","aa3e770a76","73ba67845f","77231c9a5d","fdbb4d79b7","62a8b7c3cf","faf78acd4b","21cf49b2a9","6fee2a99f5","11b584e916","7b43dbb731","c4e35489fa","507c1dc35f","dc6b7d76b0","3362ce97f6","039120d108","38642424e0","00c3db66ee","f57cc01d89","90890097b9","12e85aae7e","acc113866a","28f6ae40ff","38642424e0","00c3db66ee","f57cc01d89","90890097b9","12e85aae7e","acc113866a","28f6ae40ff","d7f40b0a12","70e45ccd7d","c787ea5273","42503e88c8","7c26da61d4","bd9e6604aa","acd3cee357","d7f40b0a12","70e45ccd7d","c787ea5273","42503e88c8","7c26da61d4","bd9e6604aa","acd3cee357"]}
```
