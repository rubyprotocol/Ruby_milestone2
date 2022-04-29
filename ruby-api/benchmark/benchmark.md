We run postman to test the latency of our client modules based on inner product and quadratic functional encryption schemes. We run our experiments on a remote server with 2.5 GHz Intel Core i7. All the tests are run in a single thread. The following data is the total time it takes to complete the full process, i.e., from the data owner uploading the original data to a data purchaser obtaining the final decryption results. We run the experiments on data vectors of lengths 2, 4, 6, and 10. 

[Innerproduct]| 2 | 4 | 6 | 10 
------ | ------ | ------ | ------ | ------
total time | 12053 ms | 24113 ms | 30043 ms |  51733 ms





[Quadratic]| 2 | 4 | 6 | 10 
------ | ------ | ------ | ------ | ------
total time | 21704 ms | 141920 ms | 600439 ms |  3173356 ms
