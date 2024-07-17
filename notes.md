# EVM Subchain feature estimation

## Core and Runtime

- IX: Create subchain account - (native_invoke + check big_storage)
  
  **3 days**

- IX: Execute subchain tx - (invoke_context.create_executor(chain_id), (executor without precompiles on subchain))
  
  **4 days**

- In core - patch -> Multi patch (Option<EvmPatch> -> HashMap<Chainid, EvmPatch>)
  
  **1 day**

- in core - multi sysvar -> blockhashes (\* KVS or SYSVARs or EVM_STATE_ACCOUNT). (on bank.freeze() -> for subchain in subchains{})
  
  **1 week**
<!--
```rust
    (Map<slot:Hash>[limit 256] | [Hash;256] + Slot) .execute_tx() -> map.update(slot, new_hash);
    fn map_update(&mut map: BTreeMap<slot, Hash>, slot, hash) {
        map.insert(slot, hash);
        map = map.iter().take(256).collect(); // remove element with smallest slot
    }
    fn array_update(array: &mut [Hash;256], last_slot: Slot, slot: Slot, new_hash: Hash) {
        assert!(last_slot <= slot);

        if last_slot == slot {
            array[255] = new_hash
        }
        array = [array[1..].push_front(new_hash)];
    }
```
-->

- in core - last_root for multichains
  
  **3 days**

<!--
  ```rust
  fn hash_internal_state: // TODO: add hash calculation of all subchain last roots, activated by feature
  ```
-->

- in core: feature activation
  
  **3 days**

## RPC

- merge pr andrey.
  
  **1-2 day**

- change sidechain handlers
  
  **3 days**

- fix `solana_transaction_status::parse_evm`
  **1 day**

## Testing

- unit and integration
  
  **4-5 weeks+**

- deconstruct evm

- subchain execute tx

- feature activation

## Release and Integration with validators

  **4 - 7 days**

## Test cases

Create EVM Subchain config and execute mainchain/subchain txs, make sure precompiles are not activated on subchain



1. Create evm -  add pre-seed
2. Sanity check - on create subchain create - check if chainid not main.
3. Test: for native swap and evm swap 
4. test: for precompiles (evm loader program).

Update transaction-statuses
