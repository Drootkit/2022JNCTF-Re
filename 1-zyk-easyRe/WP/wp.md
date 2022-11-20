# easyRe

## 分析进程

程序整体对flag进行加密然后输出到out中。

分析可见加密过程为以下几步：

- 统计词频并进行置换
- 依据s数组进行顺序置换
- 进行位移异或和减一

依次逆向即可

### 脚本

首先统计词频：

```
s = 
"""
Twinkle_twinkle_little_star
How_I_wonder_what_you_are
Up_above_the_world_so_high
Like_a_diamond_in_the_sky
Twinkle_twinkle_little_star
How_I_wonder_what_you_are
When_the_blazing_sun_is_gone
When_he_nothing_shines_upon
Then_you_show_your_little_light
Twinkle_twinkle_all_the_night
Twinkle_twinkle_little_star
How_I_wonder_what_you_are
Then_the_traveller_in_the_dark
Thanks_you_for_your_tiny_spark
Could_he_see_which_way_to_go
If_you_did_not_twinkle_so
Twinkle_twinkle_little_star
How_I_wonder_what_you_are
In_the_dark_blue_sky_you_keep
Often_through_my_curtains_peep
For_you_never_shut_your_eye
Till_the_sun_is_in_the_sky
Twinkle_twinkle_little_star
How_I_wonder_what_you_are
"""
out = {}
for i in s:
    out.update({i:s.count(i)})
out = sorted(out.items())
print(out)
```

整理后得出以下结果：

```
 ('C', 1),
 ('F', 1),
 ('U', 1), 
 ('I', 7), 
 ('L', 1), 
 ('O', 1),
 ('z', 1)
 ('c', 2),
 ('W', 2),
 ('m', 2), 
('b', 3),
 ('v', 3),
('f', 3), 

 ('H', 5), 
('p', 6),
('g', 8),
 ('T', 10), 
 ('d', 13), 
('y', 20), 
('u', 21), 

 ('s', 22), 
('k', 22),

('\n', 25),
 ('a', 27), 
('r', 29),
 ('w', 32),
 ('h', 33), 
 ('l', 36), 
 ('i', 37), 
('o', 39), 
 ('n', 42), 
 ('t', 49), 
 ('e', 62), 
('_', 110),
```

将重复频数的删除：

```
 ('H', 5), 
('p', 6),
('g', 8),
 ('T', 10), 
 ('d', 13), 
('y', 20), 
('u', 21), 
('\n', 25),
 ('a', 27), 
('r', 29),
 ('w', 32),
 ('h', 33), 
 ('l', 36), 
 ('i', 37), 
('o', 39), 
 ('n', 42), 
 ('t', 49), 
 ('e', 62), 
('_', 110),
```

写整体脚本：

```

mapp = {'x':0,'H':5,'p':6,'g':8,'T':10,'d':13,'y':20,'u':21,'a':27,'r':29,'w':32,'h':33,'l':36,'i':37,'o':39,'n':42,'t':49,'e':62,'_':110}

def decypt():
    enc = open("out","rb").read()
    d0 = []
    temp = enc[len(enc)-1] & 0x7
    for i in range(len(enc)):
        d0.append((temp << 5) | (enc[i] >> 3))
        temp = enc[i] & 0x7

# d0[0]  = 32
    flag = []
    print(d0)
    for i in d0:
        flag.append(list(mapp.keys())[list(mapp.values()).index(i)])
    return "JNCTF{%s}" % ''.join(flag)


print(decypt())
```

其中第一位没有直接得出，从词频中找有意义的字符串，得到w，进而得到flag。

```
JNCTF{well_you_are_really_High_eyyyyyy_poger}
```



统计

位移加密

