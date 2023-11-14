// SPDX-License-Identifier: GPL-3.0
// import "github.com/Arachnid/solidity-stringutils/strings.sol";
pragma solidity >=0.7.0 <0.9.0;

contract GMHL {

    uint transaction_id = 0x153ef8aa9574bb46c51df3ad42e34664ea369d6a9f4ac577eeb5ccf4bcde44b6;
    // address payable owner;

    // constructor() public payable{
    //     owner = msg.sender;
    //     msg.value;
    // }

    function calculate(bytes32 alpha, uint beta) public payable returns (bool) {
        uint sum = transaction_id+beta;
        bytes32 hash = keccak256(abi.encode(sum));
        if (hash==alpha){
            address payable addr1 = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
            svalue(addr1);
            return true;
        }
        else{
            return false;
        } 
    }

    function svalue(address payable addr) public payable{
        addr.transfer(1*10**18);
    }

    // fallback() external payable{}

}