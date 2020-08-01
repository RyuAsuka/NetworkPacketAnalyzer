"""
FlowStatistics
==============

基于 `numpy` 定义了 `FlowStatistics` 类。用于封装对某个流特征的统计量。

支持的统计量
------------
count
    计数值
sum
    求和
min
    最小值
max
    最大值
mean
    平均值
std
    标准差
variacne
    方差
"""


import numpy as np


class FlowStatistics(object):
    """
    对统计信息和统计函数的封装。
    """
    def __init__(self):
        self._inner_data = []

    def add_value(self, value):
        """
        向统计表中添加值。

        Parameters
        ----------
        value: int or float
            要加入的值
        """
        self._inner_data.append(value)

    def count(self):
        """
        返回统计表中的计数值。

        Returns
        -------
        int:
            计数值。
        """
        return len(self._inner_data)

    def sum(self):
        """
        计算当前统计表的和。

        Returns
        -------
        int or float:
            当前统计表的和。
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.sum(npa)

    def min(self):
        """
        计算当前统计表中的最小值。

        Returns
        -------
        int or float:
             当前统计表中的最小值。
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.min(npa)

    def max(self):
        """
        计算当前统计表中的最大值。

        Returns
        -------
        int or float:
            当前统计表中的最大值。
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.max(npa)

    def mean(self):
        """
        计算当前统计表中所有数值的均值。

        Returns
        -------
        float:
            当前统计表中的均值。
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.mean(npa)

    def variance(self):
        """
        计算当前统计表中所有数值的方差。

        Returns
        -------
        float:
            当前统计表中的方差。
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.var(npa)

    def std(self):
        """
        计算当前统计表中所有数值的标准差。

        Returns
        -------
        float:
            当前统计表中的标准差。
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.std(npa)
