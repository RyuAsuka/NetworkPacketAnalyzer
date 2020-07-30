"""
全局的 ID 生成器。每次使用时使用 next_id() 方法，获得下一个 ID。
"""


class IdGenerator(object):
    """
    ID 生成器类。

    Attributes
    ----------
    id: int
        生成的全局 ID。
    """
    def __init__(self, id=0):
        self.id = id

    def next_id(self):
        """
        获得下一个 ID。

        Returns
        -------
        int:
            下一个 ID。
        """
        self.id += 1
        return self.id
