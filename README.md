# SM3
## SM3概述
SM3密码杂凑算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。具体算法标准原始文本参见参考文献[1]。该算法于2012年发布为密码行业标准(GM/T 0004-2012)，2016年发布为国家密码杂凑算法标准(GB/T 32905-2016)。  

SM3适用于商用密码应用中的数字签名和验证，是在[SHA-256]基础上改进实现的一种算法，其安全性和SHA-256相当。SM3和MD5的迭代过程类似，也采用Merkle-Damgard结构。消息分组长度为512位，摘要值长度为256位。 

整个算法的执行过程可以概括成四个步骤：消息填充、消息扩展、迭代压缩、输出结果。  

## 消息填充
SM3的消息扩展步骤是以512位的数据分组作为输入的。因此，我们需要在一开始就把数据长度填充至512位的倍数。数据填充规则和MD5一样，具体步骤如下：  

1、先填充一个“1”，后面加上k个“0”。其中k是满足(n+1+k) mod 512 = 448的最小正整数。  

2、追加64位的数据长度（bit为单位，大端序存放1。观察算法标准原文附录A运算示例可以推知。）  


## 消息扩展
SM3的迭代压缩步骤没有直接使用数据分组进行运算，而是使用这个步骤产生的132个消息字。（一个消息字的长度为32位/4个字节/8个16j进制数字）概括来说，先将一个512位数据分组划分为16个消息字，并且作为生成的132个消息字的前16个。再用这16个消息字递推生成剩余的116个消息字。  

## 迭代压缩
在上文已经提过，SM3的迭代过程和MD5类似，也是Merkle-Damgard结构。但和MD5不同的是，SM3使用消息扩展得到的消息字进行运算。  


初值IV被放在A、B、C、D、E、F、G、H八个32位变量中，其具体数值参见参考文献[1]。整个算法中最核心、也最复杂的地方就在于压缩函数。压缩函数将这八个变量进行64轮相同的计算。  




最后，再将计算完成的A、B、C、D、E、F、G、H和原来的A、B、C、D、E、F、G、H分别进行异或，就是压缩函数的输出。这个输出再作为下一次调用压缩函数时的初值。依次类推，直到用完最后一组132个消息字为止。  

## 输出结果
将得到的A、B、C、D、E、F、G、H八个变量拼接输出，就是SM3算法的输出。  
