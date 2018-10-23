# Resolve Hashed Functions

The project provides an IDA Python script to automate the resolution of hashed functions in shellcode. 

### Prerequisites

In order for the script to resolve the hashed function names an appropriate rainbow table first needs to be generated. Please note that, the current version of this utility requires you to modify the code to select the dynamic link library of interest.

```
python generation/generateRainbowTable.py
```

## Deployment

In order to successfully run the script, you need to make sure that the generated rainbow table is present in the current working directory

## Authors

* **Christian Giuffre** - *Initial work* - [int3rrupted](https://github.com/int3rrupted)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details