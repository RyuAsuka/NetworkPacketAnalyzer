"""
The `FlowStatistics` class is defined based on `numpy`.

It encapsulates the statistics of a certain flow feature.

+----------------------+
| Supported statistics |
+======================+
| Count                |
+----------------------+
| Summation            |
+----------------------+
| Maximum              |
+----------------------+
| Minimum              |
+----------------------+
| Mean (Average)       |
+----------------------+
| Standard Deviation   |
+----------------------+
| Variance             |
+----------------------+
"""


import numpy as np


class FlowStatistics(object):
    """
    Encapsulate the statistics of a flow.

    Attributes
    ----------
    _inner_data : list of int or list of float
        The inner array of statistics.
    """
    def __init__(self):
        self._inner_data = []

    def add_value(self, value):
        """
        Add value to the inner data list.

        Parameters
        ----------
        value: int or float
            The value to be added.
        """
        self._inner_data.append(value)

    def count(self):
        """
        Returns the count of current data table.

        Returns
        -------
        int
           The count value.
        """
        return len(self._inner_data)

    def sum(self):
        """
        Calculate the sum of inner data table.

        Returns
        -------
        int or float
            The sum of data table.
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.sum(npa)

    def min(self):
        """
        Calculate the minimum of inner data table.

        Returns
        -------
        int or float
            The minimum value in the table.
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.min(npa)

    def max(self):
        """
        Calculate the maximum of inner data table.

        Returns
        -------
        int or float
            The maximum value in the table.
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.max(npa)

    def mean(self):
        """
        Calculate the mean value of inner data table.

        Returns
        -------
        float
            The mean value of inner data table.
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.mean(npa)

    def variance(self):
        """
        Calculate the variance value of inner data table.

        Returns
        -------
        float
            The variance value of inner data table.
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.var(npa)

    def std(self):
        """
        Calculate the standard deviation value of inner data table.

        Returns
        -------
        float
            The standard deviation value of inner data table.
        """
        if len(self._inner_data) == 0:
            return 0
        npa = np.array(self._inner_data)
        return np.std(npa)
