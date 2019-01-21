# Illumio-coding-challenge
Submission for Illumio coding challenge

## Testing
Tested this solution based on various combination of direction,protocol,port and ip address.Ran test for edge cases as well.These test cases are present in the solution.

## Implementation
The Firewall class consists of a constructor which accepts a csv filepath(This file contains the Network rules),main problem was to add the range defined for port and IP address in this rules. All this rules had to be stored to check for the incoming inputs. Add each rule to  HashSet including the range for which port and IP addresses were defined.Overrode equals method in order to state that 2 network rule are similar when direction, protocol, port and IP address are same.

## Refinements
Could add Validation to each input fields.

## Teams
Platform Team
